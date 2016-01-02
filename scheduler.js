var fs = require('fs');
var progress = require('progressbar-stream');
var split = require('split');
var ip = require('ip');
var i2cbuild = require('ip2country/src/build');
var i2clookup = require('ip2country/src/lookup');

// Default parameter for how many entries can be in clientLists / clientSuccess
// before those caches are culled.
exports.maxActive = 2048;

// ip->asn map. filled by init.
var asnmap;

// DB of:  asn->[ips]
var servers = {};
// See computeBuckets, meant to provide diversity w/o overwhelming any given server.
var buckets = [];

// Map of ip -> [servers]
var clientLists = {};
var clientSuccess = {};

// Add a server to `servers` as streamed in from file.
var addServer = function (ip) {
  var asn = asnmap(ip);
  if (!servers[asn]) {
    servers[asn] = [];
  }
  servers[asn].push(ip);
};

// Compute `buckets` from the asn->ips DB.
var computeBuckets = function () {
  // Precomputation to allow calculation from client IPs to diverse set of servers
  // that they should be scheduled with.
  var bigASNs = Object.keys(servers).filter(function(k) {return servers[k].length > 15;});
  var smallASNs = Object.keys(servers).filter(function(k) {return servers[k].length <= 15;});
  var i;
  var openBucket;

  for (i = 0; i < bigASNs.length; i += 1) {
    buckets.push(servers[bigASNs[i]]);
  }
  openBucket = [];
  for (i = 0; i < smallASNs.length; i += 1) {
    openBucket = openBucket.concat(servers[smallASNs[i]]);
    if (openBucket.length > 15) {
      buckets.push(openBucket);
      openBucket = [];
    }
  }
  console.log('Ideally clients will test against' + buckets.length + ' resolvers');
};

var getServers = function (client) {
  var ipn = ip.toLong(client);
  var entries = [];
  // Initial bucket indexes.
  for (var i = 0; i < buckets.length; i += 1) {
    entries.push(i);
  }
  // Permute keyed on client IP.
  entries.sort(function (i, j) {
    var a = (ipn & (1 << (i % 32))) !== 0;
    var b = (ipn & (1 << (j % 32))) !== 0;
    return a - b;
  });
  // Map to server.
  return entries.map(function (idx) {
    var bucket = buckets[idx];
    return bucket[ipn % bucket.length];
  });
};

/**
 * load from a server database for IPs of resolvers to test.
 */
exports.init = function (db, cb) {
  i2cbuild.getGenericMap(false, false).then(function(map) {
    asnmap = i2clookup.lookup.bind({}, map);
    var input = fs.createReadStream(db);
    var length = fs.statSync(db).size;
    input
        .pipe(progress({total: length}))
        .pipe(split())
        .on('data', addServer)
        .on('end', function () {
          computeBuckets();
          cb();
        });
    });
};

/**
 * Get a server to try for a client. Stable until the success() is called
 * for that pair
 */
exports.getServer = function (client) {
  if (clientLists[client] && clientLists[client].length) {
    // Reset TTL
    clientLists[client][clientLists[client].length - 1] = new Date().valueOf();
    return clientLists[client][0];
  } else {
    clientLists[client] = getServers(client);
    clientLists[client].push(new Date().valueOf());
    return clientLists[client][0];
  }
};

/**
 * Check if a client has been able to talk to a server.
 */
exports.isSuccess = function (client, server) {
  return clientSuccess[client] && clientSuccess[client][server] === true;
};

/**
 * Record that a client has talked to a server.
 */
exports.record = function (client, server, success) {
  if (clientLists[client] && clientLists[client][0] == server) {
    // record
    if (!clientSuccess[client]) {
      clientSuccess[client] = {};
    }
    clientSuccess[client][server] = success;
    clientSuccess[client].lastUpdate = new Date().valueOf();

    // Step forwards.
    clientLists[client].shift();
    // Just TTL left.
    if (clientLists[client].length === 1) {
      delete clientLists[client];
      delete clientSuccess[client];
    }
  }

  if (Object.keys(clientLists).length > exports.maxActive || Object.keys(clientSuccess).length > exports.maxActive) {
    cullCaches();
  }
};

exports.cullCaches = function () {
  // Clean clientLists.
  var times = Object.keys(clientLists).map(function (client) { return clientLists[client][clientLists[client].length - 1];});
  var median = times.sort()[math.floor(times.length / 2)];
  var keys = Object.keys(clientLists);
  keys.forEach(function (client) {
    if (clientLists[client][clientLists[client].length - 1] < median) {
      delete clientLists[client];
    }
  });
  // clean clientSuccess
  times = Object.keys(clientSuccess).map(function (client) { return clientSuccess[client].lastUpdate;});
  median = times.sort()[math.floor(times.length / 2)];
  keys = Object.keys(clientSuccess);
  keys.forEach(function (client) {
    if (clientSuccess[client].lastUpdate < median) {
      delete clientSuccess[client];
    }
  });
};

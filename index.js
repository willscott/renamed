var checksum = require('crc-32');
var dns = require('native-dns');
var winston = require('winston');

var scheduler = require('./scheduler');
winston.level = 'debug';
winston.cli();

if (process.argv.length < 5) {
  console.log('Usage: renamed <domain name> <public IP of server> <alt IP of server> <serveripfile>');
  process.exit();
}
var rootTLD = process.argv[2].toLowerCase();
var myip = process.argv[3];
var altip = process.argv[4];
scheduler.init(process.argv[5]);
var sessionDigestKey = require('uuid').v4();
var prefilling = {};

var createChecksum = function (client, server) {
  var str = client + '-' + server + '-' + sessionDigestKey;
  str = str.replace(/\./g, 'a').replace(/:/g, 'b');
  return Math.abs(checksum.str(str));
};

// Return [client,server] if query is valid, or false if not.
var validateQuery = function (query) {
  query = query.replace(/a/g, '.').replace(/b/g, ':');
  var parts = query.split('-');
  if (parts.length != 3) {
    return false;
  }
  var client = parts[0];
  var server = parts[1];
  var expectedChecksum = createChecksum(client, server);
  if (parts[2] === '' + expectedChecksum) {
    return [client, server];
  } else {
    return false;
  }
};

var setRootAuthority = function(resp, noA) {
  resp.authority.push(dns.NS({
    name: rootTLD,
    data: 'ns1.' + rootTLD,
    ttl: 5
  }));
  resp.authority.push(dns.NS({
    name: rootTLD,
    data: 'ns2.' + rootTLD,
    ttl: 5
  }));
  if (!noA) {
    resp.answer.push(dns.A({
      name: 'ns1.' + rootTLD,
      address: myip,
      ttl: 5
    }));
    resp.answer.push(dns.A({
      name: 'ns2.' + rootTLD,
      address: altip,
      ttl: 5
    }));
  }
  resp.authority.push(dns.SOA({
    name: rootTLD,
    primary: 'ns1.' + rootTLD,
    admin: 'measurement.' + rootTLD,
    serial: new Date().valueOf(),
    refresh: 5,
    retry: 5,
    expiration: 5,
    minimum: 5,
    ttl: 5
  }));
};

var setDelegatedAuthority = function(prefix, resp) {
  var delegatedCN = prefix + '.' + rootTLD;
  resp.authority.push(dns.NS({
    name: delegatedCN,
    data: 'ns1.' + delegatedCN,
    ttl: 5
  }));
  resp.authority.push(dns.NS({
    name: delegatedCN,
    data: 'ns2.' + delegatedCN,
    ttl: 5
  }));
};


var matchServer = function (client) {
  // Seem to need 2 servers for resolver to be happy. One can be a
  // blackhole though.
  var blackhole = '127.0.0.1';
  var server = [scheduler.getServer(client), blackhole];
  return server;
};

var createPrefix = function (client, server) {
  var checksum = createChecksum(client, server);
  var prefix = client + '-' + server + '-' + checksum;
  return prefix.replace(/\./g, 'a').replace(/:/g, 'b');
};

// make a query to populate a server cache, so it can answer non-recursively
// despite not being authoritative
var fillCache = function (prefix, server, cb) {
  var question = dns.Question({
    name: prefix,
    type: 'A'
  });
  var req = dns.Request({
    question: question,
    server: { address: server, port: 53, type: 'udp'},
    timeout: 1000
  });
  req.on('end', cb);
  req.send();
};

var handler = function (req, resp) {
  if (req.question.length === 0) {
    return;
  }
  var query = req.question[0].name.toLowerCase();
  var addr = req.address.address;
  var prefix, resolvers;

  if (req.question[0].type != 1 && req.question[0].type != 2 && req.question[0].type != 28 && req.question[0].type != 255) {
    winston.debug(addr + ' IN ' + req.question[0].type + ' ' + query + ': Ignored');
  } else if (req.question[0].type == 2) { // NS request
    winston.debug(addr + ' IN NS ' + query + ': Local Authority Proven');
    setRootAuthority(resp);
    resp.send();
    return;
  } else if (req.question[0].type == 1 || req.question[0].type === 28 || req.question[0].type == 255) { // A/ANY request
    var lookuptype = (req.question[0].type == 255) ? 'ANY' : (req.question[0].type == 28) ? 'AAAA' : 'A';
    var debugline = addr + ' IN ' + lookuptype + ' ' + query + ': ';
    // Failures
    if (query.indexOf(rootTLD) === -1) {
      winston.debug(debugline, 'Ignored');
      return;
    } else if (query === "ns1." + rootTLD || query === "ns2." + rootTLD) {
      setRootAuthority(resp);
      resp.send();
      winston.debug(debugline, 'Local Authority Proven');
      return;
    } else if (query === rootTLD) {
      // Initial Query
      resolvers = matchServer(addr);
      prefix = createPrefix(addr, resolvers[0]);
      var delegatedCN = prefix + '.' + rootTLD;
      if (prefilling[delegatedCN]) {
        // Time out until prefilling complete.
        winston.debug(debugline, 'Ignored - prefill in progress.');
        return;
      }
      winston.info(debugline, 'Initial Request. Matched to ' + resolvers[0]);
      resp.header.ra = false;
      resp.answer.push(dns.CNAME({
        name: query,
        ttl: 5,
        data: 'resolve.' + delegatedCN
      }));
      setDelegatedAuthority(prefix, resp);
      resp.additional.push(dns.A({
        name: 'ns1.' + delegatedCN,
        address: resolvers[0],
        ttl: 5
      }));
      resp.additional.push(dns.A({
        name: 'ns2.' + delegatedCN,
        address: resolvers[1],
        ttl: 5
      }));
      prefilling[delegatedCN] = true;
      winston.debug('Initiating request for ' + delegatedCn + ' to ' + resolvers[0]);
      fillCache('resolve.' + delegatedCN, resolvers[0], function() {
        setTimeout(function (resp) {
          delete prefilling[delegatedCN];
          winston.debug(debugline, 'CNAME to ' + resolvers[0]);
          resp.send();
        }.bind({}, resp), 1000);
      });
      return;
    }

    // Successful indicaton of connectivity
    prefix = query.split(rootTLD)[0];
    prefix = prefix.substr(0, prefix.length - 1);
    var host = '';
    if (prefix.indexOf('.') > 0) {
      host = prefix.split('.');
      prefix = host[1];
      host = host[0];
    } else if (prefix.indexOf('success-') === 0) {
      host = 'success';
      prefix = prefix.substr(8);
    }
    var parts = validateQuery(prefix);
    if (parts === false) {
      resp.answer.push(dns.A({
        name: query,
        address: myip,
        ttl: 5
      }));
      resp.send();
      winston.debug(debugline, 'Local A Record');
      return;
    } else if (host === 'ns1' || host === 'ns2') {
      setDelegatedAuthority(prefix, resp);
      resolvers = matchServer(parts[0]);
      resp.answer.push(dns.A({
        name: 'ns1.' + prefix + '.' + rootTLD,
        address: resolvers[0],
        ttl: 5
      }));
      resp.answer.push(dns.A({
        name: 'ns2.' + prefix + '.' + rootTLD,
        address: resolvers[1],
        ttl: 5
      }));
      resp.send();
      winston.debug(debugline, 'NS to ' + resolvers[0]);
      return;
    } else if (host === 'success') {
      if (prefilling[prefix + '.' + rootTLD]) {
        // in induced recursive resolution. follow cname redirection with servfail.
        resp.answer.push(dns.A({
          name: query,
          ttl: 5,
          address: myip
        }));
        resp.send();
        winston.debug(debugline, '[prefill probe] Self A');
        return;
      }
      if (!scheduler.isSuccess(parts[0], parts[1])) {
        winston.debug(debugline, 'First Successful Resolution');
        winston.info('Success: ' + addr + ' resolved domain in cache of ' + parts[1] + '. [initiated by ' + parts[0] + ']');
        scheduler.success(parts[0], parts[1], true);
        resp.answer.push(dns.A({
          name: query,
          address: addr,
          ttl: 5
        }));
        resp.send();
        return;
      } else {
        winston.debug(debugline, 'Subsqeuent Successful Resolution');
        resp.answer.push(dns.A({
          name: query,
          address: myip,
          ttl: 5
        }));
        resp.answer.push(dns.TXT({
          name: query,
          ttl: 5,
          data: "This prefix was seeded to " + parts[1] + " at initial request of " + parts[0]
        }));
        resp.send();
        return;
      }
    } else {
      // Queries for the cname are owned by the appropriate delegee.
      if (prefilling[prefix + '.' + rootTLD]) {
        // "poison" the cache of the authoritative resolver.
        setDelegatedAuthority(prefix, resp);
        resp.answer.push(dns.CNAME({
          name: "resolve." + prefix + '.' + rootTLD,
          ttl: 20,
          data: "success-" + prefix + '.' + rootTLD
        }));
        resp.additional.push(dns.A({
          name: "success-" + prefix + '.' + rootTLD,
          ttl: 1,
          address: myip
        }));
        resp.send();
        winston.debug(debugline, '[prefill probe] CNAME answer');
        return;
      }
      if (addr == parts[0]) {
        setDelegatedAuthority(prefix, resp);
        resolvers = matchServer(parts[0]);
        resp.additional.push(dns.A({
          name: 'ns1.' + prefix + '.' + rootTLD,
          address: resolvers[0],
          ttl: 5
        }));
        resp.additional.push(dns.A({
          name: 'ns2.' + prefix + '.' + rootTLD,
          address: resolvers[1],
          ttl: 5
        }));
        resp.send();
        winston.debug(debugline, 'Delegated NS');
        return;
      } else {
        winston.debug(debugline, 'Unexpected subdomain request. Returning A for safety.');
        resp.answer.push(dns.A({
          name: query,
          address: addr,
          ttl: 5
        }));
        resp.send();
        return;
      }
    }
  }
};

var server1 = dns.createServer();
server1.on('request', handler);
server1.on('error', function (err) {
  console.warn(err.stack);
});
var server2 = dns.createServer();
server2.on('request', handler);
server2.on('error', function (err) {
  console.warn(err.stack);
});


server1.serve(53, myip);
server2.serve(53, altip);
winston.info('Running for', rootTLD, myip, altip);
winston.info('Session Key is', sessionDigestKey);

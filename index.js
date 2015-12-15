var checksum = require('crc-32');
var dns = require('native-dns');
var winston = require('winston');
winston.cli();

if (process.argv.length < 4) {
  console.log('Usage: renamed <domain name> <public IP of server> <alt IP of server>');
  process.exit();
}
var rootTLD = process.argv[2].toLowerCase();
var myip = process.argv[3];
var altip = process.argv[4];
var server = dns.createServer();
var sessionDigestKey = require('uuid').v4();

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

var matchServer = function (client) {
  var server = '208.67.220.220'; //todo: roundrobin.
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

server.on('request', function (req, resp) {
  if (req.question.length === 0) {
    return;
  }
  var query = req.question[0].name.toLowerCase();
  var addr = req.address.address;

  if (req.question[0].type != 1 && req.question[0].type != 2) {
    winston.info(addr + '[' + req.question[0].type + '] ' + query);
  } else if (req.question[0].type == 2) { // NS request
    winston.info(addr + '[NS] ' + query);
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
    resp.additional.push(dns.A({
      name: 'ns1.' + rootTLD,
      address: myip,
      ttl: 5
    }));
    resp.additional.push(dns.A({
      name: 'ns2.' + rootTLD,
      address: altip,
      ttl: 5
    }));
    resp.send();
    return;
  } else if (req.question[0].type == 1) { // A request
    winston.info(addr + '[A] ' + query);
    // Failures
    if (query.indexOf(rootTLD) === -1) {
      resp.answer.push(dns.A({
        name: query,
        address: myip,
        ttl: 5
      }));
      resp.send();
      return;
    // Initial query
    } else if (query === "ns1." + rootTLD || query === "ns2." + rootTLD) {
      resp.answer.push(dns.A({
        name: 'ns1.' + rootTLD,
        address: myip,
        ttl: 5
      }));
      resp.answer.push(dns.A({
        name: 'ns2.' + rootTLD,
        address: myip,
        ttl: 5
      }));
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
      resp.send();
      return;
    } else if (query === rootTLD) {
      // TODO: record attempt at connectivity
      var resolver = matchServer(addr);
      var delegee = createPrefix(addr, resolver) + '.' + rootTLD;
      resp.header.ra = false;
      resp.answer.push(dns.CNAME({
        name: query,
        ttl: 5,
        data: 'resolve.' + delegee
      }));
      resp.authority.push(dns.NS({
        name: delegee,
        data: 'ns1.' + delegee,
        ttl: 5
      }));
      resp.authority.push(dns.NS({
        name: delegee,
        data: 'ns2.' + delegee,
        ttl: 5
      }));
      resp.additional.push(dns.A({
        name: 'ns1.' + delegee,
        address: resolver,
        ttl: 5
      }));
      resp.additional.push(dns.A({
        name: 'ns2.' + delegee,
        address: resolver,
        ttl: 5
      }));
      fillCache('precache.' + delegee, resolver, function() {
        resp.send();
      });
      return;
    }

    // Successful indicaton of connectivity
    var prefix = query.split(rootTLD)[0];
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
      return;
    } else if (host === 'ns1' || host === 'ns2') {
      resp.answer.push(dns.A({
        name: query,
        address: parts[1],
        ttl: 5
      }));
      resp.authority.push(dns.SOA({
        name: prefix,
        primary: 'ns1.' + prefix + '.' + rootTLD,
        admin: 'measurement.' + rootTLD,
        serial: new Date().valueOf(),
        refresh: 5,
        retry: 5,
        expiration: 5,
        minimum: 5,
        ttl: 5
      }));
      resp.send();
      return;
    } else if (host === 'precache') {
      // "poison" the cache of the authoritative resolver.
      resp.answer.push(dns.A({
        name: query,
        address: myip,
        ttl: 5
      }));
      resp.additional.push(dns.CNAME({
        name: "resolve." + prefix + '.' + rootTLD,
        ttl: 5,
        data: "success-" + prefix + '.' + rootTLD
      }));
      resp.send();
      return;
    } else if (host === 'success') {
      winston.info('Induced Connectivity between ' + parts[0] + ' and ' + parts[1] + ' via cache poisoning [seen by ' + addr + ']');
      resp.answer.push(dns.A({
        name: query,
        address: addr,
        ttl: 5
      }));
      resp.send();
      return;
    } else {
      // Queries for the cname are owned by the appropriate delegee.
      if (addr == parts[0]) {
        resp.authority.push(dns.NS({
          name: prefix + '.' + rootTLD,
          ttl: 5,
          data: 'ns1.' + prefix + '.' + rootTLD
        }));
        resp.authority.push(dns.NS({
          name: prefix + '.' + rootTLD,
          ttl: 5,
          data: 'ns2.' + prefix + '.' + rootTLD
        }));
        resp.additional.push(dns.A({
          name: 'ns1.' + prefix + '.' + rootTLD,
          address: parts[1],
          ttl: 5
        }));
        resp.additional.push(dns.A({
          name: 'ns2.' + prefix + '.' + rootTLD,
          address: parts[1],
          ttl: 5
        }));
        resp.send();
        return;
      } else {
        // TODO: Log success of client-server. query.
        // TODO: See if it's been made recently by same server, indicating response dropped.
        winston.info('Induced Connectivity between ' + parts[0] + ' and ' + parts[1] + ' [exposed as ' + addr + ']');
      /*
      resp.answer.push(dns.CNAME({
        name: query,
        ttl: 5,
        data: 'www.google.com'
      }));
      */
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
});

server.on('error', function (err) {
  console.warn(err.stack);
});

server.serve(53, myip);
winston.info('Running for', rootTLD, myip);
winston.info('Session Key is', sessionDigestKey);

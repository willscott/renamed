var checksum = require('crc-32');
var dns = require('native-dns');
var winston = require('winston');
winston.cli();

if (process.argv.length < 4) {
  console.log('Usage: renamed <domain name> <public IP of server>');
  process.exit();
}
var rootTLD = process.argv[2].toLowerCase();
var myip = process.argv[3];
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
  var server = '8.8.8.8'; //todo: roundrobin.
  return server;
};

var createPrefix = function (client, server) {
  var checksum = createChecksum(client, server);
  var prefix = client + '-' + server + '-' + checksum;
  return prefix.replace(/\./g, 'a').replace(/:/g, 'b');
};

server.on('request', function (req, resp) {
  if (req.question.length > 0 && req.question[0].type == 1) {
    var query = req.question[0].name.toLowerCase();
    var addr = req.address.address;
    winston.info(addr + ': ' + query);
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
        primary: 'ns1' + rootTLD,
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
        data: delegee
      }));
      resp.authority.push(dns.SOA({
        name: delegee,
        primary: 'ns1' + delegee,
        admin: 'measurement.' + rootTLD,
        serial: new Date().valueOf(),
        refresh: 5,
        retry: 5,
        expiration: 5,
        minimum: 5,
        ttl: 5
      }));
      resp.authority.push(dns.NS({
        name: delegee,
        data: 'ns1.' + delegee,
        ttl: 5
      }));
      resp.additional.push(dns.A({
        name: 'ns1.' + delegee,
        address: resolver,
        ttl: 5
      }));
      resp.send();
      return;
    }

    // Successful indicaton of connectivity
    var prefix = query.split(rootTLD)[0];
    prefix = prefix.substr(0, prefix.length - 1);
    var parts = validateQuery(prefix);
    if (parts === false) {
      resp.answer.push(dns.A({
        name: query,
        address: myip,
        ttl: 5
      }));
      resp.send();
      return;
    } else {
      // Queries for the cname are owned by the appropriate delegee.
      if (addr == parts[0]) {
        resp.authority.push(dns.NS({
          name: query,
          ttl: 5,
          data: 'ns1.' + query
        }));
        resp.additional.push(dns.A({
          name: 'ns1.' + query,
          address: parts[1],
          ttl: 5
        }));
        resp.send();
        return;
      } else {
        // TODO: Log success of client-server. query.
        // TODO: See if it's been made recently by same server, indicating response dropped.
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

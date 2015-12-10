var dns = require('native-dns');
var checksum = require('crc-32');

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
  str = str.replace(/\./g, 'a').replace(/:/g, 'b')
  return checksum.str(str);
}

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
  if (parts[2] === expectedChecksum) {
    return [client, server];
  } else {
    return false;
  }
}

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
    console.log(addr + ':' + query);
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
    } else if (query === rootTLD) {
      // TODO: record attempt at connectivity
      var server = matchServer(addr);
      var delegee = createPrefix(addr, server) + '.' + rootTLD;
      resp.answer.push(dns.CNAME({
        name: query,
        ttl: 5,
        data: delegee
      }));
      resp.additional.push(dns.NS({
        name: delegee,
        ttl: 5,
        data: 'ns1.' + delegee
      }));
      resp.additional.push(dns.A({
        name: 'ns1.' + delegee,
        address: server,
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
      // TODO: Log success of client-server. query.
      // TODO: See if it's been made recently by same server, indicating response dropped.
      resp.answer.push(dns.CNAME({
        name: query,
        ttl: 5,
        data: 'www.google.com'
      }));
      resp.answer.push(dns.A({
        name: 'www.google.com',
        address: '173.194.123.52',
        ttl: 5
      }));
      resp.send();
      return;
    }
  }
});

server.on('error', function (err) {
  console.warn(err.stack);
});

server.serve(53);

renamed: a reflective named server
----------------------------------

renamed is an implementation of a measurement technique to determine if
a DNS client is capable of communicating with a remote DNS server, and to
learn about DNS consistency issues on those remote connections.

technique
---------

Renamed works by asking clients to perform a unique CNAME redirection
through a remote server. When a recursive DNS server does its
resolution, it will not request further resolution, so the challenge
faced is that the remote server will not know the answer that
it should give for this unique sub-domain. To address this, renamed
directly queries the remote server to populate its cache with an
authoritative answer (in the form of another CNAME redirect) for
the sub-domain. This means that if a client comes back to renamed
asking for the second CNAME, it was successfully able to contact
and learn the cached value in the remote server. If it does not,
but comes back asking for the first CNAME again, we learn that
communication with the remote server failed.

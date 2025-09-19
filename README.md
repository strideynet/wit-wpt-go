# wit-wpt-go

Experimental WIMSE WIT/WPT & SPIFFE support in Go along with examples of WPT
usage on various protocols.

Much of the functionality here may eventually end up merged into
`spiffe/go-spiffe`.

As per https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-protocol/

It should go without saying that this code is currently not production ready
and is mostly hacked together :')

## Details

### gRPC

gRPC supports the concept of "metadata" which is sent with requests and
responses - similar to HTTP headers. These are commonly used for
authentication credentials.

We can use this metadata in place of HTTP headers to send the WIT and WPT as
described by the Workload to Workload draft. For consistency, we reuse the same
names for the metadata keys as specified in the draft for HTTP:

- `Workload-Identity-Token` for the WIT
- `Workload-Presentation-Token` for the WPT

It's worth noting that in some gRPC implementations (e.g. Connect RPC), these
will literally be sent as HTTP headers in certain circumstances.

See `transport/grpc` for implementation details.

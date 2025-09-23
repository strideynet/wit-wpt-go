# wit-wpt-go

Experimental WIMSE WIT/WPT & SPIFFE support in Go along with examples of WPT
usage on various protocols.

As per https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-protocol/

There's some extended remarks included within this README that may be of
interest to those trying to apply WPT to non-HTTP protocols.

Much of the functionality here may eventually end up merged into
`spiffe/go-spiffe`.

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

It's worth noting that the default gRPC transport implementation is HTTP/2 under
the hood, and, with this transport, this metadata is literally sent as HTTP/2 
headers.

See `transport/grpc` for implementation details.

#### Audience Claim

The `aud` claim of the WPT is likely to be the most interesting claim when it
comes to gRPC, or indeed, any protocol other than HTTP.

For HTTP, the W2W spec states:

> The audience SHOULD contain the HTTP target URI (Section 7.1 of [RFC9110]) of
> the request to which the WPT is attached, without query or fragment parts.

For the most part, gRPC does use HTTP/2 as transport under the hood. Because of
this, perhaps the simplest thing to do would be to leverage the scheme, 
authority and path of the HTTP/2 request. For example, a gRPC request to the
`UnaryEcho` RPC of the `grpc.examples.echo.Echo` service on a server at 
`echo.svc.example.com:443` would have an `aud` of
`https://echo.svc.example.com:443/grpc.examples.echo.Echo/UnaryEcho`.

However, this behaviour presents some of the usual challenges seen with `aud`
historically and some more unique to gRPC:

- The server cannot usually determine automatically the authority at which it
  will be accessible due to the use of load balancers etc. This requires manual
  configuration by an operator.
- The server may be accessible at multiple authorities (e.g. an external and
  internal address). This requires the manual configuration of multiple 
  acceptable authority values by an operator.
- The use of ALPN can allow multiple different implementations of the same gRPC
  service and RPC to be served at the same authority. This is not something I
  have seen in practice but does present some interesting ideas around whether
  using the authority (e.g hostport) does truly identify the intended recipient
  of the request.

I find myself wondering the hostport/authority is the most natural fit to
identify a recipient workload in the WIMSE world. Perhaps leveraging the WIMSE
workload identifier of the intended recipient would be better, although this
comes with its own drawbacks:

- It may not be easy for the client to determine the workload identifier of the
  server without manual configuration by an operator.
- Hypothetically, there is nothing stopping WIT/WPT being used for client
  authentication in cases where the client holds a WIMSE workload identifier but
  the server itself does not. 

Ultimately, it is likely sensible that whilst the SDK should ship a default
behaviour, it should be easily overridden with an alternative behaviour by the
operator to suit their infrastructure.
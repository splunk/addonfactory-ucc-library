# README

Splunk TA UCC Library Python (splunktaucclib) is an open source helper library used by Splunk Add-ons.
This library is used by Splunk Add-on builder, and Splunk UCC based add-ons and is intended for use by partner
developers. This SDK/Library extends the Splunk SDK for python.

## Communication channels

If you are a Splunker use: https://splunk.slack.com/archives/C03T8QCHBTJ

If you are a part of the community use: https://splunk-usergroups.slack.com/archives/C03SG3ZL4S1

## Support

Splunk TA UCC Library is an open source product developed by Splunkers. This library is not "Supported Software" by Splunk, Inc. issues and defects can be reported via the public issue tracker.

## Search-head input-page guard

On classic-cloud Search Heads and Search Head Cluster members, modular input
schemes are typically stripped at deploy time. When a customer opens the
"Inputs" tab of a UCC-generated add-on in that environment, the underlying
REST call fails and the React UI shows a generic "Something Went Wrong" page.

To produce an actionable message instead, `AdminExternalHandler.handleList`
detects this situation and raises:

```
Inputs cannot be configured on this instance. You don't have input-page
access on this Search Head. Inputs for <add-on> must be configured on the
IDM. Please contact your admin or Splunk Support.
[code=INPUTS_NOT_ALLOWED_ON_THIS_INSTANCE]
```

The guard only fires when **all** of the following hold:

1. The endpoint is a `DataInputModel` (configs/settings tabs are untouched).
2. The current instance is a pure Search Head / SHC member (instances that
   also carry an input-owning role such as `indexer`, `heavyweight_forwarder`,
   `cluster_slave`, etc. are excluded).
3. The underlying call returned a 5xx — or a 404 that is not a legitimate
   "name does not exist" / "is already in use" entity error.
4. A follow-up probe of `/data/modular-inputs/<kind>` confirms the scheme is
   not registered (or the probe itself cannot be performed). If the scheme
   is verifiably registered, the original error is propagated so transient
   splunkd / KV store failures are not masked.

### Emergency escape hatch

Set `SPLUNKTAUCC_DISABLE_SH_INPUT_GUARD=1` on the splunkd process to skip
the guard entirely and restore pre-fix behavior. This is intended for
diagnostics only.

## License

* Configuration and documentation licensed subject to [APACHE-2.0](LICENSE)

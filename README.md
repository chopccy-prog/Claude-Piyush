# Claude-Piyush

Instrument-to-ERP integration work.

## masslynx_bridge/

A Python service that continuously ships **Waters MassLynx** LC-MS audit-trail
and sample-result exports to a central ERP / LIMS server.

See [`masslynx_bridge/README.md`](masslynx_bridge/README.md) to get started, and
[`masslynx_bridge/docs/EAR_FORMAT_ANALYSIS.md`](masslynx_bridge/docs/EAR_FORMAT_ANALYSIS.md)
for the analysis of the MassLynx `.EAR` backup format and why integration should
be built on MassLynx's supported exports rather than on the encrypted `.ear`.

## invoicing/

A small generator for professional consulting invoices: JSON in, A4 PDF out,
with one shared design. See [`invoicing/README.md`](invoicing/README.md).

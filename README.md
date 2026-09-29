# Claude-Piyush

Instrument-to-ERP integration work.

## masslynx_bridge/

A Python service that continuously ships **Waters MassLynx** LC-MS audit-trail
and sample-result exports to a central ERP / LIMS server.

See [`masslynx_bridge/README.md`](masslynx_bridge/README.md) to get started, and
[`masslynx_bridge/docs/EAR_FORMAT_ANALYSIS.md`](masslynx_bridge/docs/EAR_FORMAT_ANALYSIS.md)
for the analysis of the MassLynx `.EAR` backup format and why integration should
be built on MassLynx's supported exports rather than on the encrypted `.ear`.

## magicnet_dat_extractor/

Tools for the **Metrohm MagIC Net 3.3** ion-chromatography database
(`objects.dat` / `objects.idx` / `DBInfo` / `eventlog` / `recovery`), which is an
embedded Versant FastObjects 10 object store rather than an encrypted per-run
file. Includes a complete event-log parser, a forensic inspector to run on the
instrument PC, a salvage extractor and a spec-driven decoder that mirrors the
Access `extract.py` flags.

See [`magicnet_dat_extractor/README.md`](magicnet_dat_extractor/README.md) and
[`magicnet_dat_extractor/docs/FINDINGS.md`](magicnet_dat_extractor/docs/FINDINGS.md).

# webapi-on-lakebase

OHDSI WebAPI and ATLAS as a Databricks App, with WebAPI's own database on Lakebase. This file names the concepts of this repo.

## Language

**Pinned artifact**:
A set of files the app downloads at start and runs, fixed by a digest in the code: the JRE, the WebAPI files, the ATLAS files and the Databricks JDBC driver. The PgBouncer binary is not one: its digest comes from your config.
_Avoid_: dependency, download, asset

**Known host**:
A host that the download of a pinned artifact may contact, redirect targets included. The README lists every known host for sites that restrict outbound network access.
_Avoid_: egress endpoint, allowed domain

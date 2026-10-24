# 0004. Store the extracted text and the file's hash, not the uploaded file

## Situation

The interface shows each quote in the surrounding text, and "run again" repeats a review without a new upload, so the server
needs the document's text after the request ends. The uploaded file itself holds more than the text: images, metadata such as
author names and revision history, embedded files.

## Decision

The application stores the **passages extracted from the document** (with page, section and paragraph spans), the file name,
its size and its **SHA-256**, and never the uploaded bytes. Deleting a review removes its passages, findings and the cached
answers it created. A retention period (`HIPAA_AUDIT_RETENTION_DAYS`) and `hipaa-audit purge` remove old reviews.

## Why

- It stores less, and less of what is likely to be sensitive beyond the policy text: no embedded images, author metadata or
  tracked changes.
- The hash says which file was reviewed without keeping it, so two reviews of the same file can be recognised.
- It keeps the database small and simple.

## Consequences

- The text is still the policy, so the database is sensitive. See [security.md](../security.md).
- A better parser cannot be applied to a stored review later. The user uploads the file again.
- The web framework may spool an upload over 1 MB to a temporary file while the request is read, and deletes it when the request
  ends. The application does not keep it.
- Deleted rows are not securely erased from the database file. Retention and an encrypted volume are the controls.

## Considered

- Storing nothing and keeping the text only in memory. It rules out the context view and "run again" and loses everything on a
  restart.
- Storing the original file, encrypted. More to protect, more to expire, and no feature needs it.

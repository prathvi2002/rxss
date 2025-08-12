Based on tomnomnom's kxss tool, with added options and support for path-embedded parameters.

Effective usage example: 
`cat urls.txt | grep = | urlnodupe | rxss --threads 15 --output-worthy pxss_urls.txt --raw-payload`

# TODO:
- Fix the error, details in `error/` directory.
- Option to follow redirect and check for unfiltered special characeters in those parameters.
- Add pxss option to check only for specific special characters.
- `--refcheck` not working maybe, check and fix it.

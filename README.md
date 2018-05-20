# dmarc-monitoring
A tool for monitoring and analysing DMARC aggregate reports for a domain.

## Saving incoming reports automatically

To save reports automatically to MYSQL using a procmail filter, write a little
script like that:

```shell
#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR
if [ ! -f ./.venv/bin/python ]
then
    virtualenv -p python3 .venv
    ./.venv/bin/pip install -r requirements.txt
fi
./.venv/bin/python ./dmarc_pipe.py --user myUser --password myPassword --database myDatabase --host=myHost
```

Then add something like that to your .procmailrc to invoque that script:

```procmailrc
:0Hc:
* ^Subject: \[Root\] Report Domain:
| $HOME/src/dmarc-monitoring/dmarc_pipe
```

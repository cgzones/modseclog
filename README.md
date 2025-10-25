# modseclog

[![Version info](https://img.shields.io/crates/v/modseclog.svg)](https://crates.io/crates/modseclog)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE?raw=true)

`modseclog` is a graphical terminal application for viewing and analyzing [`ModSecurity`](https://github.com/owasp-modsecurity/ModSecurity) logs.
It helps in finding and fine-tuning problematic requests and rules.

## How to use

Either run `modseclog` and manually select the log files to analyse or specify the log files via command line arguments:

```
modseclog /var/log/apache/modsec_audit.*
```

## License

[Apache 2.0 License](LICENSE?raw=true)

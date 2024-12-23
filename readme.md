# FRR OSFP API Stream Client

This repository contains a Python client for the [FRR OSPF API](https://docs.frrouting.org/projects/dev-guide/en/latest/ospf-api.html) 
which synchronizes a copy of the network's LSDB via LSA update streams for export into various formats:
 1. Fixed JSON snapshots in the format of the [Bird OSFP Link Database Parser](https://github.com/Andrew-Dickinson/bird-ospf-link-db-parser)
 2. A continuous stream of changes, filtered from the original LSA stream to only include changes which actually influence the network graph or injected routes

This work is based in large part on the [reference script](https://github.com/FRRouting/frr/blob/master/ospfclient/ospfclient.py) 
included in FRR. You should start there if you are trying to develop your own
custom FRR OSPF API client.

```
> ospf-stream-client -s <frr OSPF API server addr>
2024-12-23 04:29:32,352 WARNING: CLIENT: root Waiting for initial load to complete...
2024-12-23 04:29:32,465 WARNING: CLIENT: root LSDB loaded!
{"timestamp": 1734928168632, "entity": {"type": "router", "id": "10.69.5.52"}, "added": {"link": {"router": {"id": "10.69.6.10", "metric": 100}}}}
{"timestamp": 1734928167633, "entity": {"type": "router", "id": "10.69.6.10"}, "added": {"link": {"router": {"id": "10.69.5.52", "metric": 100}}}}
{"timestamp": 1734928166886, "entity": {"type": "router", "id": "10.69.3.85"}, "removed": {"link": {"router": {"id": "10.69.4.40", "metric": 100}}}}
{"timestamp": 1734928165886, "entity": {"type": "router", "id": "10.69.1.65"}, "added": {"link": {"router": {"id": "10.69.5.51", "metric": 100}}}}
{"timestamp": 1734928164890, "entity": {"type": "router", "id": "10.69.5.51"}, "added": {"link": {"router": {"id": "10.69.1.65", "metric": 100}}}}
```


## Output Format

The DB snapshot and streamed updates output formats are detailed using 
[JSON Schema](https://json-schema.org/) in `src/api_stream_client/db_snapshot.json` 
and `src/api_stream_client/stream_event.json` respectively. Note that the stream 
is composed of a series of newline-delimited JSON objects, each of which is formatted
according to `stream_event.json`. This means the stream (and any subset of its lines) is 
JSONL-compliant. Read more about JSONL [here](https://jsonlines.org/).

## Usage

Pre-requisites: `python3` available via the shell

First, install the CLI via pip:
```shell
pip install frr-ospf-api-stream-client
```

then invoke the tool with the CLI command:
```shell
ospf-stream-client -s <frr OSPF API server adress>
```

Available flags:
- `--abc`: def

## Dev Setup

Pre-requisites: `python3` available via the shell

Setup by cloning, creating a virtual env, and installing the application
```sh
git clone https://github.com/Andrew-Dickinson/frr-ospf-api-stream-client
cd frr-ospf-api-stream-client
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

then invoke the tool with the CLI command:
```sh
frr-ospf-api-stream-client -s <frr OSPF API server adress>
```

## Running the unit tests

Follow the instructions under "Dev Setup" above, to clone a local copy of this application and activate
the virtual environment. Then installing the test dependencies with:
```sh
pip install -e ".[test,dev]"
```

Finally, invoke the test suite using pytest:
```
pytest test/
```

## Building to PyPi

Follow the instructions above to clone a local copy of this application, activate
the virtual environment, and run the tests.

Then, build & upload the application with
```
rm -rf dist/*
python -m build .
twine upload dist/*
```

## License

Distributed under the GPL-2.0 License. See `license.txt` for more information.

## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request


## Acknowledgments
 * [Best-README-Template](https://github.com/othneildrew/Best-README-Template/)
 * [FRR OSPF API Python Example](https://github.com/FRRouting/frr/blob/master/ospfclient/ospfclient.py)
 * [RFC 2328](https://datatracker.ietf.org/doc/html/rfc2328)
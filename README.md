
<h1 align="center">Agent VirusTotal</h1>

<p align="center">
<img src="https://img.shields.io/badge/License-Apache_2.0-brightgreen.svg">
<img src="https://img.shields.io/github/languages/top/ostorlab/agent_virus_total">
<img src="https://img.shields.io/github/stars/ostorlab/agent_virus_total">
<img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg">
</p>

_VirusTotal is an agent that scans for viruses in a file using the VirusTotal public API._

---

<p align="center">
<img src="https://github.com/Ostorlab/agent_virus_total/blob/main/images/logo.png" alt="agent_virus_total" />
</p>

This repository is an implementation of the VirusTotal agent.

## Getting Started
To perform your first scan, simply run the following command.
```shell
ostorlab scan run --install --agents agent/ostorlab/virustotal --file malware.exe
```

This command will download and install `agent/ostorlab/virustotal` and targets the file `malware.exe`.
For more information, please refer to the [Ostorlab Documentation](https://github.com/Ostorlab/ostorlab/blob/main/README.md)


## Usage

Agent VirusTotal can be installed directly from the ostorlab agent store or built from this repository.

 ### Install directly from ostorlab agent store

 ```shell
 ostorlab agent install agent/ostorlab/virustotal
 ```

You can then run the agent with the following command:
```shell
ostorlab scan run --agents agent/ostorlab/virustotal --file malware.exe
```


### Build directly from the repository

 1. To build the virustotal agent you need to have [ostorlab](https://pypi.org/project/ostorlab/) installed in your machine.  if you have already installed ostorlab, you can skip this step.

```shell
pip3 install ostorlab
```

 2. Clone this repository.

```shell
git clone https://github.com/Ostorlab/agent_virus_total.git && cd agent_virus_total
```

 3. Build the agent image using ostorlab cli.

 ```shell
 ostortlab agent build --file=ostorlab.yaml
 ```
 You can pass the optional flag `--organization` to specify your organisation. The organization is empty by default.

 4. Run the agent using one of the following commands:
	 * If you did not specify an organization when building the image:
      ```shell
      ostorlab scan run --agents agent//virustotal --file malware.exe
      ```
	 * If you specified an organization when building the image:
      ```shell
      ostorlab scan run --agents agent/[ORGANIZATION]/virustotal --file malware.exe
      ```


## License
[Apache](./LICENSE)


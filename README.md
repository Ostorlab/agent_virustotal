
# Agent Virus Total
![enter image description here](https://github.com/Ostorlab/agent_virus_total/blob/README/images/logo.png)
An implementation of [Osorlab Agent]((https://pypi.org/project/ostorlab/) for the [Nmap](https://nmap.org/).    
  
## Usage  
  
Refer to Ostorlab documentation.  
  
### Install directly from ostorlab agent store.  
  
`ostorlab agent install agent/ostorlab/agent_virus_total`  
  
### Build directly from the repository  
  
 1. To build the tsunami agent you need to have [ostorlab](https://pypi.org/project/ostorlab/) installed in your machine.  if you have already installed ostorlab you can skip this step.  
   
`pip3 install ostorlab`    
3. clone this repository.  
   
`git clone https://github.com/Ostorlab/agent_virus_total.git && cd agent_virus_total`  
 4. build the agent image using ostorlab cli.  
  
 `ostortlab agent build --file=ostorlab.yaml`
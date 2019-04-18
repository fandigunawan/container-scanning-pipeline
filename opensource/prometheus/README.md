# Prometheus Installation Instructions
This is an example of how to run a dockerized hardened prometheus container that can monitor a Cluster with the use of node_exporters and EC2 Service Discovery tools built into Prometheus.

### Pre-requisites
 - EC2 Instance for prometheus use
 - Bastion w/ ansible & node groups pre-defined

### Installation Steps
##### Prometheus Installation
1). ssh into your prometheus instance, and subscribe to additional repos to have access to docker etc.:
example Commad:


    subscription-manager unregister; \
    subscription-manager clean; \
    rpm -Uvh http://ip-10-0-1-76.us-gov-west-1.compute.internal/pub/katello-ca-consumer-latest.noarch.rpm; \
    rm -rf /etc/yum.repos.d/*rhui*; \
    subscription-manager register --org="Unified_Platform" --activationkey="generic_key"

2). Install docker and download the dccscr repo where the prometheus source lives

     sudo yum install docker
     git clone <dccscr repo url>

3). Edit the prometheus Dockerfile `FROM` field to point to the `ubi7-dev-hardened` image hosted on your Cluster (via nexus, docker-registry, etc)

     cd /unified-platform-dccscr/opensource/prometheus/v2.8.0/
     vi Dockerfile
     
4). Edit `prometheus.yml` in the `/scripts` directory to match your env. The following is required in order to function properly:

    vi scripts/prometheus.yml
    region: <AWS_REGION_HERE>
    access_key: <ACCESS_KEY_HERE>
    secret_key: <SECRET_KEY_HERE>
    regex: <TAG NAME TO FILTER BY>

 - Region: the aws region your cluster is running in
 - keys: Keys needed to access the instances
 - regex: The filter used for our node exporters. This example uses the tagName filter for the EC2 Instances: up-ss-ocp.* which the SD interpets as only the EC2 instances with those tag names are to be scraped; as in, those instances should have node exporters running.
 - **Note:** The port for the exporters is set as `9105` instead of the typical `9100` port used by node exporters. The reason for this change is due to the baked in node exporters already running in the cluster are already using the `9100` port, and as such we use a different port to keep the exporters separate
     
5). Build and run the prometheus Docker container
     
     sudo docker build -t prometheus:v2.8.0 .
     sudo docker run --restart=unless-stopped -d -p <PRIVATE_IP_HERE>:9090:9090 prometheus
     
6). Verify the instance is running both internally and externally

     curl <PRIVATE_IP_HERE>:9090
From local terminal
   
     curl <PUBLIC_IP_HERE>:9090
     
Congrats, Prometheus is up and running and accessible.
**Note:** If you look at your prometheus instance under targets, you'll notice that only your prometheus target is up. The OCP SD Targets are not, that is because we need to setup the node exporters on your cluster. Instructions below

##### Node Exporter Installation
The node exporter installation is relatively straightforward. Let's start off by noting that there are already security restricted node exporters running inside the cluster on every node. This is baked into the typical OCP cluster, however because we want to have Prometheus monitoring completely dettached from the cluster, we will setup our own node exporters on the same VM of the nodes, but separate and outside the Cluster's reach.

There are two ways to install the node exporters on your cluster: 
 - Via leveraging the redhat provided node-exporters already in the docker instances on each node
 - Manual installation with provided node exporter

This README will follow the first method #TODO: Flesh out second method

1). ssh into your OCP bastion, login as root, locate your ansible repos, and verify you can find your node group

     sudo su
     cd /<PATH_TO_ANSIBLE>/ (i.e /aws-vpc-build/PREDEV)
    ansible nodes -m ping
    
2). Once you have your node groups returning pings, we are ready to install node exporters on each of them:
    
    sudo ansible nodes -m shell -a 'sudo docker run --restart=always -d -p 0.0.0.0:9105:9100 registry.redhat.io/openshift3/prometheus-node-exporter:v3.11.88'
    sudo ansible nodes -m shell -a 'sudo docker ps -n 1'
    
 - The second ansible command verifies the containers are running, it should be run quickly after the first command
 - The first command tells every node, which has docker already running & has redhat's node exporter as a downloaded image, to run another node exporter on the 9105 port for our prometheus server to pick up
 - **Note:** verify you are using the proper version of node-exporters that is already installed on these nodes, if you do not specify it will attempt to download a newer version
 
Now return to your prometheus server and look at the targets tab. Notice they start to come up one by one. Congrats you have basic monitoring on all OCP nodes now!

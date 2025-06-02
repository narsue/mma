sudo docker run --name scylla --hostname some-scylla -p 9042:9042 -d scylladb/scylla --smp 1  
sudo docker container scylla start
![plot](spine-leaf-evpn-clab.png)

# Run this lab
```
sudo clab deploy -t spine-leaf-evpn.clab.yml --reconfigure
```

# Ping test
```
docker exec -it clab-spine-leaf-evpn-client1 ping 100.127.10.102 -c3
```

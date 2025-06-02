# sudo apt install -y hey

hey -n 500 -c 5 -m POST -H "Content-Type: application/json"   -d '{"email":"narsue@hotmail.com","password":"test"}'   http://127.0.0.1:1227/api/user/login

hey -n 500 -c 5 -m POST -H "Content-Type: application/json"   -d '{"email":"test@test.com","password":"test"}'   http://127.0.0.1:1227/api/user/login

hey -n 1000 -c 10 http://127.0.0.1:1227/
# toy-mysql-client

```
$ cargo run --quiet
mysql> select * from users limit 1;
[ResultsetRow(["1", "Alice"])]
mysql> invalid;
ERROR 1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'invalid' at line 1
mysql>
```

## memo

```
docker compose exec db mysql -u root -proot -h 127.0.0.1 -D test --protocol=TCP --ssl-mode=DISABLED -e "select * from users;"
```

```
hexdump -C ./docker/tcpdump/captures/mysql_capture.pcap
```

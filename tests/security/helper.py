import sys
request='''{
        "name": "my_service_name",
        "domain_list": [{"domain": "mywebsite.com"},
                        {"domain": "blog.mywebsite.com"}],
        "origin_list": [{"origin": "mywebsite1.com",
                         "port": 443,
                         "ssl": false}],
        "caching_list": [{"name": "default", "ttl": 3600},
                         {"name": "home",
                          "ttl": 1200,
                          "rules": [{"name" : "index",
                                     "request_url" : "/index.htm"}]}]
    }'''

print  "{"
for k in range(100000, 1500000, 100000):
  print "\"buffer_length%s\":{\"buffer_length\":%s}," % (k,k)
print "}"

sys.exit(-1)

with open("fuzz1.txt") as f:
    lines = f.readlines()

print  "{"

count = 0
for line in lines:
    line = line.strip()
    line = line.replace('"', '%22')
    line = line.replace('\\', '\\\\')
    print "\"fuzz_string_%s\":{\"fuzz_string\":\"%s\"}" % (count, line)

    #print request.replace("my_service_name", line)
    count += 1
    print ","

print "}"
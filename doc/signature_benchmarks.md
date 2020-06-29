# Benchmarks

## just RSA-Keys, signature over whole executable

### hello

[2020-02-29T19:24:10Z INFO  north::signature] verifying signature took 150659 us

### remote-battery-charge

[2020-02-29T19:24:38Z INFO  north::signature] verifying signature took 461175 us

### remote-lock-unlock

2020-02-29T19:24:39Z INFO  north::signature] verifying signature took 430902 us

## sha256 crypto hash + RSA keys

### hello

[2020-03-02T13:29:04Z INFO  north::signature] sha256 digest took 105705 us
[2020-03-02T13:29:04Z INFO  north::signature] verifying signature took 39109 us

## sha256 crypto hash + ECC keys

### hello

[2020-03-02T16:07:30Z INFO  north::signature] Sha256 digest took 11471 us
[2020-03-02T16:07:30Z INFO  north::signature] Verifying signature took 309 us

### Running start remote.*

[2020-03-02T16:08:02Z INFO  north::signature] Sha256 digest took 37701 us
[2020-03-02T16:08:02Z INFO  north::signature] Verifying signature took 129 us
[2020-03-02T16:08:02Z INFO  north::signature] Sha256 digest took 33166 us
[2020-03-02T16:08:02Z INFO  north::signature] Verifying signature took 116 us

## blake3 crypto hash + ECC keys

## update of running app

### hello

[2020-03-02T18:13:08Z INFO  north::signature] blake3 digest took 3643 us
[2020-03-02T18:13:08Z INFO  north::signature] Verifying signature took 168 us

### remote-lock-unlock

[2020-03-02T18:13:46Z INFO  north::signature] blake3 digest took 2973 us
[2020-03-02T18:13:46Z INFO  north::signature] Verifying signature took 119 us

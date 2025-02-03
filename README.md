# ShieldNotes


### Build Image

#### From `DockerFile`
```bash
docker build --pull --rm -f DockerFile -t shieldnotes:latest .
```

#### From `.tar`
```bash
docker load < shieldnotes.tar
```



### Use

```bash
docker run -p 3000:80 -p 3022:22 -it shieldnotes
```

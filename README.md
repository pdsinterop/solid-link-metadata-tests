# Link-Metadata Test Suite

## Installation

Just put the files in a folder accessible through the web. Make sure you use `https`, or the Solid Auth login won't work. The repository contains a specific `www/` folder.


## Update dependencies

```
npm install
npx browserify -p esmify www/assets/js/main.js -o www/assets/js/bundle.js
```


# burp-feature-flag-finder
searches for feature flags in responses and flags them as issues. not perfect but helps me find interesting stuff to match and replace.

# installation
- install standalone [jython](https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.2/jython-standalone-2.7.2.jar) version 2.7.2 for your python environment in burp
- add flagfinder.py to your extensions

# usage
- when flags are found, the issue doesn't highlight in the response where the feature flags are, so you can run a regex like the following to find it:
```re
(is|is_|enable|disable|toggle|show|hide)[a-z]+\w*":\w*(true|false|1|0)
```

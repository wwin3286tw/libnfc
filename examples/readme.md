# Examples Help
* If you want to add new features to compile at examples, please modify CMakeLists.txt
```
SET(EXAMPLES-SOURCES
  nfc-mfreadblock //new source code filename
  nfc-anticol
  nfc-dep-initiator
  nfc-dep-target
  nfc-emulate-forum-tag2
  nfc-emulate-tag
  nfc-emulate-uid
  nfc-mfsetuid
  nfc-poll
  nfc-relay
  nfc-st25tb
  pn53x-diagnose
  pn53x-sam
  pn53x-tamashell
)
```
* If you are using Visual Studio and need to add new libraries, consider dragging additional code/libraries here
![image](https://user-images.githubusercontent.com/7022841/225528748-c3c90839-40e3-470c-8f12-ba89ff3c70d2.png)

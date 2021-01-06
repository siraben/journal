# A simple journal written in C
This was written a few months after I started learning C on my own in
high school.  I did not version control at the time so the last
modification was at 2018-04-07, likely earlier.  It was surprisingly
stable and I used it for a period of time to store an encrypted
journal.

It supports a command line interface for reading/writing journal
entries from a binary file format, which can be encrypted as well.  An
example session is shown below.

*Note:* I really didn't know what I was doing with libsodium at the
time, so please don't rely on this for storing secrets!

## Example session
```
$ nix-build
$ ./result/bin/journal
Welcome to Ben's Journal, type "help" for a list of available commands.
> help
Available commands are [save/create/load/append/print/delete/help/info/format/search/list]
> create
New journal name: demo
Journal was created.
(UNSAVED) > append
Enter title of entry
================================================================
First post    

Enter contents of entry
----------------------------------------------------------------
This is the first post. I can type up to 4096 characters, and
can type newlines. To finish, end the post with a hash.#
Adding entry at block 1.
(UNSAVED) > > list
There is 1 entry

Entry 1: First post
================================================================
(UNSAVED) > save
Save journal as: demo
Journal "demo" successfully saved to "demo".
```

## License
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at
your option) any later version.

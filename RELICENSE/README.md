# ospd-openvas contribution agreement

Our code is license as `AGPL-3.0-or-later`. We want to make sure that no problems accure when relicensing. Your contributions are licensed under `MIT-0` and instantly relicensed to our currently used license.
Please read and commit the /template/template.txt as [Name].md in this folder with your first PR. Having a valid `git.user.name` and `git.user.email` is sufficient.

Example usage:

```
# check with e.g. `git config --list` if you have a valid `user.name` and `user.email` set.
$ git config --list
    user.email=Jane.Doe@example.com
    user.name=jane Doe
    ....

# Commit the template
$ cd {path_to_ospd-openvas}/ospd-scanner/RELICENSE
$ cp ./template/template.txt JDoe.md
$ git add JDoe.md
$ git commit
```

Happy hacking!

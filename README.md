This command is used to view important domain information, including WHOIS and Registrant data and all relevent DNS lookups.

It will colour any DNS results that resolve to one of Nexigen Digital or one of its child companies servers to easily distinguish where the domains DNS is resolving to.

If the server any of the domains DNS resolves to is owned by Nexigen Digital or one of its child companies - it will generate cPanel and WHM logins.

If the domain is registered with the domain registar Synergy Wholesale, it will generate a link to the domain in Synergy Wholesales management system.

**How to use this script:**
```
git clone https://github.com/dev-jooby/di-domain-information
cd ./di-domain-information && chmod +x di-domain-information.sh
```

**Alias Assgning for this script**
```
echo "alias di='bash $(pwd)/di-domain-information.sh'" >> ~/.bashrc
source ~/.bashrc
```

**Example commands:**
```
di domain.com
di sub.domain.com
di email@domain.com
di https://domain.com/randompath
```

**Usage guide:**
```
usage: di [-h] [-v] [-q] domain

options:
-h         Show brief help
-v         Show verbose output
-q         Skip non-critical checks & URL generation
```

# Sample CVE Dashboard for Threat Intelligence
The dashboard is mimic and showcase a real world dashboard with an internal database.<br>
BenjiBlue is a fictional company named after hiddencache's cat.

## Disclaimer
* To protect my previous employer, no propriety information and code was used in the making of this dashboard
    * The source code of this dashboard uses an open source dashboard template made by secondtruth. To view the template, credit, and licenses, please redirect [here](https://github.com/secondtruth/startmin).
    * All data dervied from this dataset is public information by using an open source Kaggle database: [CVE 2024 Database: Exploits, CVSS, OS](https://www.kaggle.com/datasets/manavkhambhayata/cve-2024-database-exploits-cvss-os).
* The raw dataset is untouched, but the data shown on the website was cleaned up slightly to make it user-friendly. For example, a CVE description will describe an Apple attack, but the `Affected OS` is marked as N/A by the original author, thus falling in the "Other" category. This was fixed by extending the table logic to include searching within the `Description` for matching keywords in respect to the operating system. Cleaning up the dataset would have taken more time than necessary, so minimal effort was utilized in order to focus on critical resources.

## Features

* Navbar with left and right menu + Sidebar
* FontAwesome Icons (Version 4.7)
* Charts and sortable Data Tables
* Dashboard including nice Info Widgets
* Tabbed Panels with optional Dropdown
* Social Login Buttons using FontAwesome Icons

### Differences to SB Admin 2

* Hero-sized Dashboard Info Widgets
* Tabbed Panels with optional Dropdown
* Left Menu in Top Navbar (optional)
* Top Navbar is black 🖤
* Up-to-date dependencies
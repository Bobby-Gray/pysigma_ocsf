# Overview:

This project contains a draft PySigma processing pipeline (sigma_ocsf.py) to convert sigma rules into the [Open Cybersecurity Schema Framework (OCSF)](https://github.com/ocsf/) format. It was based on [@mbabinski's](https://github.com/mbabinski) [insightidr backend](https://github.com/SigmaHQ/pySigma-backend-insightidr/tree/main/sigma/pipelines/insight_idr) for which Micah wrote an excellent article detailing his process on [Medium](https://micahbabinski.medium.com/creating-a-sigma-backend-for-fun-and-no-profit-ed16d20da142). I highly recommend giving it a read if you are interested in working on something similar.  

This was initially created as a proof of concept and only contains a handful of fields relevant to AWS and GCP rules currently but I intend to continue updating it as time allows. 

* I have included a validation script titled **dump_rules_with_ocsf_pipeline.py** contained in the same directory (/pipelines/ocsf) which utilizes the splunk backend to dump a json dictionary file, sigma_rules_dict.json, of rule names with their respective directory paths as keys and splunk searches as the values. 

* The __testing__ directory contains various scripts created during creation of the sigma_ocsf processing pipeline which perform various actions against a sigma rules directory. I am working on cleaning these up for various alternative use cases like scraping rules for detection selection values to use in event tagging or similar. 



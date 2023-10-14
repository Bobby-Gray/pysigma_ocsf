# sigmocsf

# (Draft)

# Overview:

A python script to:
1. Collect Sigma formatted rules from a given repository
2. Parse the directory paths if organized by rule source/type.
3. Parse the yaml for each rule and:
  * List all logsource categories (product/service), values and add them to respective lists.
  * List all detection fields and add them to a list.
4. Gather all categories, classes, and objects from the OCSF schema docs
5. Loop through the lists of sigma categories and try to map them to the relative ocsf category.
6. Loop through the list of selection fields and try to map them to the relative ocsf class/object values.
7. Create a list of unmapped fields, if any.
8. Output a clone of the original repository with the mappings replaced, only including those where mapping was successful for all logsource categories and detection selection fields. 


4. Parse th
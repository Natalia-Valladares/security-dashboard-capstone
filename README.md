# Utilities Data Security Dashboard

## Overview
This Fall 2025 capstone project analyzes utility datasets for security risks and presents findings in a centralized dashboard. It was developed by a team of six Computer Information Systems students based on real-world data provided be a water utilities company. 

## System Architecture
 - 'utilities_data_security_dash.py' is the main UI application (developed externally and integrated into this project).
 - 'security_dash_backend.py' is the backend scanning and analysis logic. 
 - 'security_dash_functions.py' connects backend processing to the UI.

### Backend
 - Connects to source databases, runs modular security scanners, and writes results to a centralized SQLite database.  
 - Built around a scanning engine that standardizes execution across all modules.  
 - Implements multiple scanners (PII, credentials, endpoints, access, schema analysis) using a shared plugin structure.  
 - Uses a common functions layer for database access, formatting, and reusable logic.  
 - Results are stored in a unified schema, allowing the GUI to display findings without rerunning scans.

### Frontend
 - Tkinter-based GUI that presents security scan results from a centralized SQLite database.
 - Can run new scans or loading existing data.
 - Displays detailed findings at the database, table, and column level, along with aggregated risk scores and device health metrics through tab-based navigation.

## My Contribution
This was a team-based project. My contirbutions included: 
 - Coordinating team roles, sprint objectives, and timelines using Agile principles. 
 - Designing and implementing the endpoint and modem exposure scanner in the backend.
 - Structuring and standardizing output results.
 - Working with SQLite to store and retrieve scanning results. 
 - Assisting with the integration of our backend scanning modules with the UI.

## Limitations & Future Work
 - Detection relies on pattern matching and data sampling, which may lead to missed sensitive data or false positives; future improvements include more advanced detection methods to increase accuracy.  
 - Account detection depends on table and column naming conventions, limiting flexibility across different database environments; this can be improved with more adaptive identification logic.  
 - Risk scoring model is not standardized and may scale inconsistently across databases; future refinements will focus on improving scalability and transparency of scoring.  
 - Current dashboard lacks authentication and access control; adding security features is a key area for future development.
 - UI design is functional but can be improved aesthetically and expanded with features for data visualization. 

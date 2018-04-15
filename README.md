# Shodan_AssetStatus_Check
Query Shodan with a list of zones that represent assets you are interested in having a gauge on. The system will then query shodan as your cronjob runs and report on changes that occur in some zone's IP range by submitting events using CEF format to any given SIEM.

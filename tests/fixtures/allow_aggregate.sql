-- ALLOWED: an aggregate with a count column for k-anonymity to act on.
select entity_name, count(*) as n, avg(wait_minutes) as avg_wait
from analytics.core.encounter_fact
group by entity_name

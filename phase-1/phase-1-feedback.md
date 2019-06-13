# **(8/10)**
# Strong aspects
1. I espcially liked Property 4 because it reflects on the psychological acceptability and user-friendliness.
2. I liked the Group Quota property because it nicely reflecs the availability property.
3. The ideas are neat but need organization. I think you may have wanted to have multiple iterations over the report.

# Areas of improvement
1. (**-0.5**) Some conflicting assumptions and definitions.
2. You should commit early and often. All team members have to commit their respective contributions.
3. Better usage of the Markup language.
4. (**-1**) Mixing of assumptions and security properties. For example, in Property 2, you say "We are assuming the account only used by one person and that the account is not hacked." This statement is mixing a property and an assumption. The property is that each account is used by one person. The assumption is that accounts are not hacked. If the assumption is vilated, then the property may not hold any more.
5. The threat models should describe what security properties will be affected and how if/when each of the assumptions gets violated.
6. (**-0.5**) Many of the stated assumptions are not really **trust** assumptions.

# General comments
1. "we know[n] they are who they say they are" should be a separate property.
2. In Property 5, would you trust a file-sharing system that has that property?
3. In Property 3, it is not clear who exactly is the admin of the group, the group creator, some user that the creator designates? The definition of group admin is fragmented over many properties.
4. Since you mentioned user deletion, what other implications would user deletion have on the system? Would the deleted user still have access to the group files?
5. What is the difference between downloading a file and reading a file? Is there a conflict between Property 8 and 10?
6. It is really hard to have Property 13 in a _distributed_ file-sharing system.
7. Property 17 is too generic.
8. In the first threat model, "Only the user who posted a picture or the creator of the group can delete pictures." seems to be in conflict with Property 11.

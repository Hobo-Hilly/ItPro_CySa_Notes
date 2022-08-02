Episode Name: indicator management
Objectives:

Define standards used to manage and share information about threats and threat indicators.
Code Snippets:
External Resources:

    https://oasis-open.github.io/cti-documentation/
    https://misp-project.org
    https://exchange.xforce.ibmcloud.com/


These are resources that I have book marked and read.
---https://oasis-open.github.io/cti-documentation/0--

 This page is an introduction to STIX ( Structured Threat Information Expression
- Is a language and serialization format used to exchange cyber threat intelligence (CTI). STIX is Open Source and Free allowing people to contribute and ask quesetions.
- With STIX, all aspects of suspicion, compromise and attribution can be represented clearly with 
- objects and descriptive relationships. STIX information can be visually represented for an analyst or stored as JSON to be quickly machine readible. 
- STIX's openness allows for integration into existing tools and products or utilized for your specific analyst or network needs.

# Data model

 Threat actor identification is, as you would expect, represented using the Threat Actor STIX Domain Object (SDO). Information relevant to threat actors, such as goals and motivations, can be captured within this object. Other basic information not specific to threat actors, such as contact information, is best represented using an Identity SDO. Identity objects can also be used for more than threat actors in STIX. They can model organizations, government agencies, 
- and information sources to name a few.

Examples of the Structured language formats below:


JSON

{
    "type": "bundle",
    "id": "bundle--601cee35-6b16-4e68-a3e7-9ec7d755b4c3",
    "objects": [
        {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": "threat-actor--dfaa8d77-07e2-4e28-b2c8-92e9f7b04428",
            "created": "2014-11-19T23:39:03.893Z",
            "modified": "2014-11-19T23:39:03.893Z",
            "name": "Disco Team Threat Actor Group",
            "description": "This organized threat actor group operates to create profit from all types of crime.",
            "threat_actor_types": [
                "crime-syndicate"
            ],
            "aliases": [
                "Equipo del Discoteca"
            ],
            "roles": [
                "agent"
            ],
            "goals": [
                "Steal Credit Card Information"
            ],
            "sophistication": "expert",
            "resource_level": "organization",
            "primary_motivation": "personal-gain"
        },
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--733c5838-34d9-4fbf-949c-62aba761184c",
            "created": "2016-08-23T18:05:49.307Z",
            "modified": "2016-08-23T18:05:49.307Z",
            "name": "Disco Team",
            "description": "Disco Team is the name of an organized threat actor crime-syndicate.",
            "identity_class": "organization",
            "contact_information": "disco-team@stealthemail.com"
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--a2e3efb5-351d-4d46-97a0-6897ee7c77a0",
            "created": "2020-02-29T18:01:28.577Z",
            "modified": "2020-02-29T18:01:28.577Z",
            "relationship_type": "attributed-to",
            "source_ref": "threat-actor--dfaa8d77-07e2-4e28-b2c8-92e9f7b04428",
            "target_ref": "identity--733c5838-34d9-4fbf-949c-62aba761184c"
        }
    ]
}
\


# Python Producer
from stix2.v21 import (ThreatActor, Identity, Relationship, Bundle)

threat_actor = ThreatActor(
    id="threat-actor--dfaa8d77-07e2-4e28-b2c8-92e9f7b04428",
    created="2014-11-19T23:39:03.893Z",
    modified="2014-11-19T23:39:03.893Z",
    name="Disco Team Threat Actor Group",
    description="This organized threat actor group operates to create profit from all types of crime.",
    threat_actor_types=["crime-syndicate"],
    aliases=["Equipo del Discoteca"],
    roles=["agent"],
    goals=["Steal Credit Card Information"],
    sophistication="expert",
    resource_level="organization",
    primary_motivation="personal-gain"
)

identity = Identity(
    id="identity--733c5838-34d9-4fbf-949c-62aba761184c",
    created="2016-08-23T18:05:49.307Z",
    modified="2016-08-23T18:05:49.307Z",
    name="Disco Team",
    description="Disco Team is the name of an organized threat actor crime-syndicate.",
    identity_class="organization",
    contact_information="disco-team@stealthemail.com"
)

relationship = Relationship(threat_actor, 'attributed-to', identity)

bundle = Bundle(objects=[threat_actor, identity, relationship])


# Python Consumer

from stix2.v21 import (Bundle)

for obj in bundle.objects:
    if obj == threat_actor:
        print("------------------")
        print("== THREAT ACTOR ==")
        print("------------------")
        print("ID: " + obj.id)
        print("Created: " + str(obj.created))
        print("Modified: " + str(obj.modified))
        print("Name: " + obj.name)
        print("Description: " + obj.description)
        print("Threat Actor Types: " + str(obj.threat_actor_types))
        print("Aliases: " + str(obj.aliases))
        print("Roles: " + str(obj.roles))
        print("Goals: " + str(obj.goals))
        print("Sophistication: " + obj.sophistication)
        print("Resource Level: " + obj.resource_level)
        print("Primary Motivation: " + obj.primary_motivation)

    elif obj == identity:
        print("------------------")
        print("== IDENTITY ==")
        print("------------------")
        print("ID: " + obj.id)
        print("Created: " + str(obj.created))
        print("Modified: " + str(obj.modified))
        print("Name: " + obj.name)
        print("Description: " + obj.description)
        print("Identity Class: " + obj.identity_class)
        print("Contact Information: " + obj.contact_information)

    elif obj == relationship:
        print("------------------")
        print("== RELATIONSHIP ==")
        print("------------------")
        print("ID: " + obj.id)
        print("Created: " + str(obj.created))
        print("Modified: " + str(obj.modified))
        print("Type: " + obj.type)
        print("Relationship Type: " + obj.relationship_type)
        print("Source Ref: " + obj.source_ref)
        print("Target Ref: " + obj.target_ref)



# Synopsis


Identifying a Threat Actor Profile

Commercial threat intelligence providers and well-resourced government agencies often attribute malicious activity to a particular threat actor or actor group.
Scenario

In this scenario, a threat actor group named “Disco Team” is modeled using STIX Threat Actor and Identity objects. Disco Team operates primarily in Spanish and they have been known to steal credit card information for financial gain. They use the e-mail alias “disco-team@stealthemail.com” publicly and are known alternatively as “Equipo del Discoteca”.
Data model

Threat actor identification is, as you would expect, represented using the Threat Actor STIX Domain Object (SDO). Information relevant to threat actors, such as goals and motivations, can be captured within this object. Other basic information not specific to threat actors, such as contact information, is best represented using an Identity SDO. Identity objects can also be used for more than threat actors in STIX. They can model organizations, government agencies, and information sources to name a few.

It is important to note that the Disco Team group operates as a Threat Actor and not an Intrusion Set in this scenario. They could potentially support an intrusion set, but that information is unknown. An Intrusion Set is best used to describe an entire attack set that would include multiple campaigns and purposes. In this instance, Disco Team is a self-named threat actor operating with one purpose in mind.

The name and threat_actor_types properties are the only required properties needed for a Threat Actor SDO. The threat_actor_types field is important for describing what type of threat actor Disco Team is. Because Disco Team is regarded as large, organized, and driven to steal financial information, they are best represented with the threat actor type crime-syndicate.

The Threat Actor SDO can also model optional properties that construct a more complete threat actor profile. The aliases field, for instance, contains a list of other names this threat actor is known to be called. A threat actor may also have one or more roles that describe more about what they do. For instance, a threat actor could sponsor or direct attacks, author malware, or operate malicious infrastructure. In the case of Disco Team, they operate as an agent, carrying out attacks that steal financial information on behalf of themselves.

Like most threat actors, Disco Team has a specific goal in mind for their attacks. Therefore, a list of goals describes what the threat actor is trying to do. In this case, Disco Team’s only goal is stealing credit card credentials. Threat actors also have varying degrees of expertise, so the sophistication level of the attacker, if known, can describe the attacker’s skill and knowledge. Disco Team is labeled as expert due to advanced attack methods and proficiency with tools or malicious code. Their resource_level of organization indicates that they are large and well-funded, more so than smaller individuals or teams. Finally, threat actors usually have one or several motivations behind their attacks. The primary_motivation field describes the main reason for attacking. Some threat actors may seek notoriety or dominance, while others are strictly doing it for revenge or personal satisfaction. For Disco Team, obtaining financial information falls under the motivation of personal-gain.

Basic identifying information of the threat actor can be modeled with the Identity SDO. For Disco Team, they are a type of organization, which the identity_class field captures. This is due to this threat actor being more formal and organized, rather than an individual hacker or informal group of hackers. Another property that captures contact_information, if known for the identity, represents any email addresses or phone numbers. For Disco Team, an email address is provided.

Now that the information for Disco Team is represented in the Threat Actor and Identity SDO’s, the Relationship SRO links the two objects together. In this example, the source_ref threat actor id is attributed-to the target_ref identity id:

A diagram of this relationship below shows the Threat Actor and Identity SDO’s and the Relationship SRO (An interactive version can be found here):






# TAXII


Introduction to TAXII

Trusted Automated Exchange of Intelligence Information (TAXII™) is an application protocol for exchanging CTI over HTTPS. ​TAXII defines a RESTful API (a set of services and message exchanges) and a set of requirements for TAXII Clients and Servers. As depicted below, TAXII defines two primary services to support a variety of common sharing models:

    Collection - A Collection is an interface to a logical repository of CTI objects provided by a TAXII Server that allows a producer to host a set of CTI data that can be requested by consumers: TAXII Clients and Servers exchange information in a request-response model.

    Channel - Maintained by a TAXII Server, a Channel allows producers to push data to many consumers and consumers to receive data from many producers: TAXII Clients exchange information with other TAXII Clients in a publish-subscribe model. Note: The TAXII 2.1 specification reserves the keywords required for Channels but does not specify Channel services. Channels and their services will be defined in a later version of TAXII.

TAXII Collections and Channels

Collections and Channels can be organized in different ways. For example, they can be grouped to support the needs of a particular trust group.

A TAXII server instance can support one or more API Roots. API Roots are logical groupings of TAXII Channels and Collections and can be thought of as instances of the TAXII API available at different URLs, where each API Root is the “root” URL of that particular instance of the TAXII API.

TAXII relies on existing protocols when possible. In particular, TAXII Servers are discovered within a network via DNS Service records (and/or by a Discovery Endpoint, described in the next section). In addition, TAXII uses HTTPS as the transport for all communications, and it uses HTTP for content negotiation and authentication.

TAXII was specifically designed to support the exchange of CTI represented in STIX, and support for exchanging STIX 2.1 content is mandatory to implement. However, TAXII can also be used to share data in other formats. It is important to note that STIX and TAXII are independent standards: the structures and serializations of STIX do not rely on any specific transport mechanism, and TAXII can be used to transport non-STIX data.

TAXII design principles include minimizing operational changes needed for adoption; easy integration with existing sharing agreements, and support for all widely used threat sharing models: hub-and-spoke, peer-to-peer, source-subscriber.
What's New in TAXII 2.1

TAXII 2.1 differs from TAXII 2.0 in the following ways:

    The DNS SRV record was changed from taxii to taxii2
    The discovery URL was changed from /taxii/ to /taxii2/
    The Manifest Resource was changed to represent individual versions of an object, instead of an object with all of its versions
    Item based pagination was removed from this version of the specification
    The section on content negotiation was updated
    The media types were changed throughout the document
    Clarification was added to say that API Roots can be relative paths as well as absolute paths
    Changed version value in API Roots to match media type
    Changed status resource to allow status on success and pending
    Add TAXII media type as Accept type in 5.4 and 5.6 since a TAXII error message could be returned
    HTTP Basic is now a SHOULD implement for the Server
    Added a DELETE object by ID endpoint
    Added a versions endpoint for object by ID.
    Added section on Server Implementation Considerations
    Added a limit URL parameter
    Added a next URL parameter
    Added a spec_versions match filter parameter
    Removed STIX media types and STIX Bundle and replaced with TAXII Envelope
    Added clarifying text around TAXII timestamps needing millisecond precision
    Cleaned up and deemphasized text around support for content other than STIX
    Added user-agent HTTP header description

























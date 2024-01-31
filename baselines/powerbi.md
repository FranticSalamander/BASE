**`TLP:CLEAR`**

# CISA M365 Security Configuration Baseline for Power BI

Microsoft 365 (M365) Power BI is a cloud-based product that facilitates self-service business intelligence dashboards, reports, datasets, and visualizations. Power BI can connect to multiple different data sources, combine and shape data from those connections, then create reports and dashboards to share with others. This Secure Configuration Baseline (SCB) provides specific policies to strengthen Power BI security.

The Secure Cloud Business Applications (BASE) project run by the Cybersecurity and Infrastructure Security Agency (CISA) provides guidance and capabilities to secure federal civilian executive branch (FCEB) agencies' cloud business application environments and protect federal information that is created, accessed, shared, and stored in those environments.

The CISA BASE SCBs for M365 help secure federal information assets stored within M365 cloud business application environments through consistent, effective, and manageable security configurations. CISA created baselines tailored to the federal government's threats and risk tolerance with the knowledge that every organization has different threat models and risk tolerance. Non-governmental organizations may also find value in applying these baselines to reduce risks.

The information in this document is being provided "as is" for INFORMATIONAL PURPOSES ONLY. CISA does not endorse any commercial product or service, including any subjects of analysis. Any reference to specific commercial entities or commercial products, processes, or services by service mark, trademark, manufacturer, or otherwise, does not constitute or imply endorsement, recommendation, or favoritism by CISA. This document does not address, ensure compliance with, or supersede any law, regulation, or other authority.  Entities are responsible for complying with any recordkeeping, privacy, and other laws that may apply to the use of technology. This document is not intended to, and does not, create any right or benefit for anyone against the United States, its departments, agencies, or entities, its officers, employees, or agents, or any other person.

## License Compliance and Copyright
Portions of this document are adapted from documents in Microsoft's [M365](https://github.com/MicrosoftDocs/microsoft-365-docs/blob/public/LICENSE) and [Azure](https://github.com/MicrosoftDocs/azure-docs/blob/main/LICENSE) GitHub repositories. The respective documents are subject to copyright and are adapted under the terms of the Creative Commons Attribution 4.0 International license. Sources are linked throughout this document. The United States government has adapted selections of these documents to develop innovative and scalable configuration standards to strengthen the security of widely used cloud-based software services.

## Assumptions
The **License Requirements** sections of this document assume the organization is using an [M365 E3](https://www.microsoft.com/en-us/microsoft-365/compare-microsoft-365-enterprise-plans) or [G3](https://www.microsoft.com/en-us/microsoft-365/government) license level at a minimum. Therefore, only licenses not included in E3/G3 are listed.


Agencies using Power BI may have a data classification scheme in place for
  the data entering Power BI.

- Agencies may connect more than one data source to their Power BI
  tenant.
- All data sources use a secure connection for data transfer to and from
  the Power BI tenant; the agency disallows non-secure connections.

## Key Terminology
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

Access to PowerBI can be controlled by the user type. In this baseline,
the types of users are defined as follows:

1.  **Internal users**: Members of the agency's M365 tenant.
2.  **External users**: Members of a different M365 tenant.
3.  **Business to Business (B2B) guest users**: External users that are
  formally invited to view and/or edit Power BI workspace content and
  are added to the agency's Azure Active Directory (Azure AD) as guest users. These users authenticate with their home organization/tenant and are granted access to Power BI
  content by virtue of being listed as guest users in the tenant's Azure AD.

> Note:
> These terms vary in use across Microsoft documentation.

# Baseline Policies

**Related Resources**

- [Sensitivity labels in Power BI \| Microsoft
  Learn](https://learn.microsoft.com/en-us/power-bi/enterprise/service-security-sensitivity-label-overview)

- [Bring your own encryption keys for Power BI \| Microsoft
  Learn](https://learn.microsoft.com/en-us/power-bi/enterprise/service-encryption-byok)

- [What is an on-premises data gateway? \| Microsoft
  Learn](https://learn.microsoft.com/en-us/data-integration/gateway/service-gateway-onprem)

- [Row-level security (RLS) with Power BI \| Microsoft
  Learn](https://learn.microsoft.com/en-us/power-bi/enterprise/service-admin-rls)

- [Power BI PowerShell cmdlets and modules references \| Microsoft
 Learn](https://learn.microsoft.com/en-us/powershell/power-bi/overview?view=powerbi-ps)

# Appendix B: Source Code and Credential Security Considerations

Exposing secrets via collaboration spaces is a security concern when
using Power BI.

For Power BI embedded applications, it is recommended to implement a
source code scanning solution to identify credentials within the code of
any app housing embedded Power BI report(s). A source code scanner can
also encourage moving discovered credentials to more secure locations,
such as Azure key vault.

Store encryption keys or service principal credentials used for
encrypting or accessing Power BI in a Key Vault, assign proper access
policies to the vault, and regularly review access permissions.

For regulatory or other compliance reasons, some agencies may need to
use BYOK, which is supported by Power BI. By default,
Power BI uses Microsoft-managed keys to encrypt the data. In Power BI
Premium, users can use their own keys for data at-rest imported
into a dataset. See [Data source and storage
considerations](https://learn.microsoft.com/en-us/power-bi/enterprise/service-encryption-byok#data-source-and-storage-considerations)
for more information.

- For Power BI embedded applications, a best practice is to implement a
  source code scanning solution to identify credentials within the code
  of the app housing the embedded Power BI report(s).

- If required under specific regulations, agencies need a strategy for
  maintaining control and governance of their keys. The BYOK functionality is one option.

**Prerequisites**

- Implementers must do their own due diligence in selecting a source
  code scanner that integrates with their specific environment.
  Microsoft documentation references an Open Web Application Security Project, [Source Code Analysis Tools](https://owasp.org/www-community/Source_Code_Analysis_Tools); which is a guide to
  third-party scanners. This baseline does not endorse or advise on the selection or
  use of any specific third-party tool.

- If BYOK is deemed to be a requirement:

  - Power BI Premium is required for BYOK.

  - To use BYOK, the Power BI tenant admin must upload data to the Power
  BI service from a Power BI Desktop (PBIX) file.

  - RSA keys must be 4096-bit.

  - Enable BYOK in the tenant.

**BYOK Implementation High-Level Steps**

Enable BYOK at the tenant level via PowerShell by first introducing the
encryption keys created and stored in Azure Key Vault to the Power BI
tenant.

Then assign these encryption keys per Premium capacity for encrypting
content in the capacity.

To enable bringing the agency's key for Power BI, the high-level
configuration steps are as follows:

1.  Add the Power BI service as a service principal for the key vault,
    with wrap and unwrap permissions.

2. Create an RSA key with a 4096-bit length (or use an existing key of
    this type), with wrap and unwrap permissions.

3. To turn on BYOK, Power BI Tenant administrators must use a set of
    Power BI [Admin PowerShell
    Cmdlets](https://learn.microsoft.com/en-us/powershell/module/microsoftpowerbimgmt.admin/?view=powerbi-ps)
    added to the Power BI Admin Cmdlets.

    Follow detailed steps in Microsoft's [Bring your own encryption keys for Power BI](https://learn.microsoft.com/en-us/power-bi/enterprise/service-encryption-byok)
    from Microsoft.

**Related Resources**

- [Bring your own encryption keys for Power BI \| Microsoft
 Learn](https://learn.microsoft.com/en-us/power-bi/enterprise/service-encryption-byok)

- [Microsoft Security DevOps Azure DevOps extension](https://learn.microsoft.com/en-us/azure/defender-for-cloud/azure-devops-extension)

- For GitHub, the agency can use the native secret scanning feature to
  identify credentials or other form of secrets within code at [About
  secret scanning \| GitHub
  docs](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning)

- [Announcing General Availability of Bring Your Own Key (BYOK) for
  Power BI
  Premium](https://powerbi.microsoft.com/en-us/blog/announcing-general-availability-of-bring-your-own-key-byok-for-power-bi-premium/)

# Appendix C: File Export and Visual Artifact Considerations

Exporting data from Power BI to image files and comma-separated value
(.csv) file format has data security implications. For example, if
row-level security (RLS) features are in use in Power BI, an export to
image or .csv could allow a user to inadvertently decouple that setting
and expose data to a party who does not have permissions or a need to
know that previously secured data. A similar scenario applies for
information protection sensitivity labels.

A message regarding this condition is provided in the Power BI tenant
settings for the particular types of exports.

In contrast to this, Power BI applies these protection settings (RLS,
sensitivity labels) when the report data leaves Power BI via a supported
export method, such as export to Excel, PowerPoint, or PDF, download to
.pbix, and Save (Desktop). In this case, only authorized users will be
able to open protected files.

**Copy and Paste Visuals**

Power BI can allow users to copy and paste visuals from Power BI reports
as static images into external applications. This could represent a data
security risk in some contexts. The agency must evaluate whether this
represents risk for its data artifacts and whether to turn this off in
the Export and Sharing Settings.

**Related Resources**

- [Sensitivity labels in Power BI \| Microsoft
  Learn](https://learn.microsoft.com/en-us/power-bi/enterprise/service-security-sensitivity-label-overview)

- [Say No to Export Data, Yes to Analyze in
  Excel](https://radacad.com/say-no-to-export-data-yes-to-analyze-in-excel-power-bi-and-excel-can-talk)

- [Power BI Governance – Why you should consider disabling Export to
  Excel](https://data-marc.com/2020/04/13/power-bi-governance-why-you-should-consider-to-disable-export-to-excel/)

**Implementation settings**

1.  In the **Power BI tenant** settings, under **Export and sharing
    settings**, administrators can opt to toggle off both **Export reports as
    image files** and **Export to .csv**.

2. In the **Power BI tenant** settings, under **Export and sharing
    settings**, administrators can opt to toggle off **Copy and paste visuals**.

**Establishing Private Network Access Connections Using Azure Private Link:**

When connecting to Azure services intended to supply Power BI datasets,
agencies should consider connecting their Power BI tenant to an Azure
Private Link endpoint and disable public internet access.

In this configuration, Azure Private Link and Azure Networking private
endpoints are used to send data traffic privately using Microsoft's
backbone network infrastructure. The data travels the Microsoft private
network backbone instead of going across the Internet.

Using private endpoints with Power BI ensures that traffic will flow
over the Azure backbone to a private endpoint for Azure cloud-based
resources.

Within this configuration, there is also the capability to disable
public access to Power BI datasets.

**High-Level Implementation Steps**

> Note:
> It is imperative that the VNET and VM are configured before
disabling public internet access.

1.  Enable private endpoints for Power BI.

2. Create a Power BI resource in the Azure portal.

3. Create a virtual network.

4. Create a virtual machine (VM).

5. Create a private endpoint.

6. Connect to a VM using Remote Desktop (RDP).

7. Access Power BI privately from the virtual machine.

8. Disable public access for Power BI.

**Related Resources**

- [Private endpoints for secure access to Power BI  \| Microsoft
  Learn](https://learn.microsoft.com/en-us/power-bi/enterprise/service-security-private-links)

- [Azure security baseline for Power BI](https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/power-bi-security-baseline)

## Best Practices for Service Principals

- Evaluate whether certificates or secrets are a more secure option for
  the implementation.
  > Note:
  > Microsoft recommends certificates over secrets.

- Use the principle of least privilege in implementing service
  principals; only provide the ability to create app registrations to
  entities requiring it.

- Instead of enabling service principals for the entire agency,
  implement for a dedicated security group.

> Note:
> This policy is only applicable if the setting **Allow service principals to use Power BI APIs** is enabled.

**`TLP:CLEAR`**

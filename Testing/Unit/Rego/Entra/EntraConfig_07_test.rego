package entra
import future.keywords
import data.report.utils.NotCheckedDetails
import data.report.utils.ReportDetailsBoolean

#
# MS.Entra.7.1v1
#--
test_AdminSignInFrequency_Correct if {
    PolicyId := "MS.Entra.7.1v1"

    Output := tests with input as {
        "conditional_access_policy_admin_sign_in_frequency" : {
            "SessionControls":  {  
                "SignInFrequency":  {                     
                    "IsEnabled":  true,
                    "Type":  "hours",
                    "Value":  4
                }
            }
        }
    }
    
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_AdminSignInFrequency_Incorrect if {
    PolicyId := "MS.Entra.7.1v1"

    Output := tests with input as {
        "conditional_access_policy_admin_sign_in_frequency" : {
            "SessionControls":  {  
                "SignInFrequency":  {                     
                    "IsEnabled":  true,
                    "Type":  "hours",
                    "Value":  2
                }
            }
        }
    }
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: 1 AdminSignInFrequency - SignInFrequency policies configured incorrectly"
}

#
# MS.Entra.7.2v1
#--
test_ApplicationEnforcedRestrictions_Correct if {
    PolicyId := "MS.Entra.7.2v1"

    Output := tests with input as {
        "conditional_access_policy_admin_sign_in_frequency" : {
            "SessionControls":  {  
                "ApplicationEnforcedRestrictions":  {
                    "IsEnabled":  false
                }
            }
        }
    }
    
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_ApplicationEnforcedRestrictions_Incorrect_V1 if {
    PolicyId := "MS.Entra.7.2v1"

    Output := tests with input as {
        "conditional_access_policy_admin_sign_in_frequency" : {
            "SessionControls":  {  
                "ApplicationEnforcedRestrictions":  {
                    "IsEnabled":  null
                }
            }
        }
    }
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: AdminSignInFrequency - ApplicationEnforcedRestrictions - 'IsEnabled' must be set to false" 
}

test_ApplicationEnforcedRestrictions_Incorrect_V2 if {
    PolicyId := "MS.Entra.7.2v1"

    Output := tests with input as {
        "conditional_access_policy_admin_sign_in_frequency" : {
            "SessionControls":  {  
                "ApplicationEnforcedRestrictions":  {
                    "IsEnabled":  true
                }
            }
        }
    }
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: AdminSignInFrequency - ApplicationEnforcedRestrictions - 'IsEnabled' must be set to false" 
}

#
# MS.Entra.7.3v1
#--
test_CloudAppSecurity_Correct if {
    PolicyId := "MS.Entra.7.3v1"

    Output := tests with input as {
        "conditional_access_policy_admin_sign_in_frequency" : {
            "SessionControls":  {  
                "CloudAppSecurity":  {
                    "IsEnabled":  false
                }
            }
        }
    }
    
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_CloudAppSecurity_Incorrect if {
    PolicyId := "MS.Entra.7.3v1"

    Output := tests with input as {
        "conditional_access_policy_admin_sign_in_frequency" : {
            "SessionControls":  {  
                "CloudAppSecurity":  {
                    "IsEnabled":  true
                }
            }
        }
    }
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: CloudAppSecurity - 'IsEnabled' must be set to false" 
}

#
# MS.Entra.7.4v1
#--
test_PersistentBrowser_Correct if {
    PolicyId := "MS.Entra.7.4v1"

    Output := tests with input as {
        "conditional_access_policy_admin_sign_in_frequency" : {
            "SessionControls":  {  
                "PersistentBrowser":  {
                    "IsEnabled":  false
                }
            }
        }
    }
    
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_PersistentBrowser_Incorrect if {
    PolicyId := "MS.Entra.7.4v1"

    Output := tests with input as {
        "conditional_access_policy_admin_sign_in_frequency" : {
            "SessionControls":  {  
                "PersistentBrowser":  {
                    "IsEnabled":  true
                }
            }
        }
    }
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: PersistentBrowser - 'IsEnabled' must be set to false" 
}

#
# MS.Entra.7.5v1
#--
test_GrantControlOperator_Correct if {
    PolicyId := "MS.Entra.7.5v1"

    Output := tests with input as {
        "conditional_access_policy_admin_sign_in_frequency" : {
            "GrantControls":  {
                          "AuthenticationStrength":  {
                                                         "AllowedCombinations":  null,
                                                         "CombinationConfigurations":  null,
                                                         "CreatedDateTime":  null,
                                                         "Description":  null,
                                                         "DisplayName":  null,
                                                         "Id":  null,
                                                         "ModifiedDateTime":  null,
                                                         "PolicyType":  null,
                                                         "RequirementsSatisfied":  null
                                                     },
                          "BuiltInControls":  [
                                                  "mfa"
                                              ],
                          "CustomAuthenticationFactors":  [

                                                          ],
                          "Operator":  "OR",
                          "TermsOfUse":  [

                                         ]
                      }
        }
    }
    
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_GrantControlOperator_Incorrect if {
    PolicyId := "MS.Entra.7.5v1"

    Output := tests with input as {
        "conditional_access_policy_admin_sign_in_frequency" : {
            "GrantControls":  {  
                "Operator":  ""
            }
        }
    }
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: GrantControls Operator must be 'OR'"  
}

#
# MS.Entra.7.6v1
#--
test_GrantControlBuiltInControls_Correct if {
    PolicyId := "MS.Entra.7.6v1"

    Output := tests with input as {
        "conditional_access_policy_admin_sign_in_frequency" : {
            "GrantControls":  {  
                "BuiltInControls":  [
                    "mfa"
                ]
            }
        }
    }
    
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_GrantControlBuiltInControls_Incorrect if {
    PolicyId := "MS.Entra.7.6v1"

    Output := tests with input as {
        "conditional_access_policy_admin_sign_in_frequency" : {
            "GrantControls":  {  
                "BuiltInControls":  [
                    ""
                ]
            }
        }
    }
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: GrantControlBuiltInControls must be set to 'mfa'"  
}


#
# MS.Entra.7.7v1
#--
test_ClientAppTypes_Correct if {
    PolicyId := "MS.Entra.7.7v1"

    Output := tests with input as {
        "conditional_access_policy_admin_sign_in_frequency" : {
            "Conditions":  {  
                "ClientAppTypes":  [
                    "browser",
                    "mobileAppsAndDesktopClients",
                    "other"
                ]
            }
        }
    }
    
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_ClientAppTypes_Incorrect if {
    PolicyId := "MS.Entra.7.7v1"

    Output := tests with input as {
        "conditional_access_policy_admin_sign_in_frequency" : {
            "Conditions":  {  
                "ClientAppTypes":  [
                    "mobileAppsAndDesktopClients",
                    "other"
                ]
            }
        }
    }
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: ClientAppTypes must be configured correctly" 
}

#
# MS.Entra.7.8v1
#--
test_IncludeApplications_Correct if {
    PolicyId := "MS.Entra.7.8v1"

    Output := tests with input as {
        "conditional_access_policy_admin_sign_in_frequency" : {
            "Conditions":  {  
                "Applications":  {
                    "IncludeApplications":  "All"
                }
            }
        }
    }
    
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement met"
}

test_IncludeApplications_Incorrect if {
    PolicyId := "MS.Entra.7.8v1"

    Output := tests with input as {
        "conditional_access_policy_admin_sign_in_frequency" : {
            "Conditions":  {  
                "Applications":  {
                    "IncludeApplications":  "Al"
                }
            }
        }
    }
    RuleOutput := [Result | Result = Output[_]; Result.PolicyId == PolicyId]

    count(RuleOutput) == 1
    not RuleOutput[0].RequirementMet
    RuleOutput[0].ReportDetails == "Requirement not met: IncludeApplications must be set to 'All'" 
}

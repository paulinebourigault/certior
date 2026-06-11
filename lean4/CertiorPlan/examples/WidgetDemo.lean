/-
  Example: Using the Certior Verification Explorer Widget
-/

import CertiorPlan
import CertiorPlan.Dsl

open CertiorPlan
open CertiorPlan.Dsl

namespace examples.WidgetDemo

def hipaaPatientLookup : PlanInfo := plan%[
  resource planBudget := 5000 @Internal,
  main budget := 5000, compliance := "hipaa", in {
    let patientId := 12345 @Public,
    let data := 1 @Sensitive ["PHI"],
    emit data
  }
]

def hipaaWidgetProps : CertiorPlan.WidgetInitProps := { planInfo := hipaaPatientLookup }

-- #widget CertiorPlan.verificationExplorerWidget hipaaWidgetProps

def soxFinancialReport : PlanInfo := plan%[
  resource planBudget := 10000 @Internal,
  main budget := 10000, compliance := "sox", in {
    let quarter := 4 @Public,
    let revenue := 1 @Restricted ["MNPI"],
    emit revenue
  }
]

def soxWidgetProps : CertiorPlan.WidgetInitProps := { planInfo := soxFinancialReport }

-- #widget CertiorPlan.verificationExplorerWidget soxWidgetProps

end examples.WidgetDemo

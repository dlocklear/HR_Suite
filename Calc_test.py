# Define the band values based on the provided table
band_values = {
    "E0": {
        "targ6et_award": 0.10,
        "business_weight": 0.50,
        "individual_weight": 0.45,
        "safety_weight": 0.05,
    },
    "E1": {
        "target_award": 0.11,
        "business_weight": 0.50,
        "individual_weight": 0.45,
        "safety_weight": 0.05,
    },
    "E2": {
        "target_award": 0.12,
        "business_weight": 0.50,
        "individual_weight": 0.45,
        "safety_weight": 0.05,
    },
    "E3": {
        "target_award": 0.15,
        "business_weight": 0.50,
        "individual_weight": 0.45,
        "safety_weight": 0.05,
    },
    "E4": {
        "target_award": 0.16,
        "business_weight": 0.50,
        "individual_weight": 0.45,
        "safety_weight": 0.05,
    },
    "E5": {
        "target_award": 0.20,
        "business_weight": 0.70,
        "individual_weight": 0.25,
        "safety_weight": 0.05,
    },
    "E6": {
        "target_award": 0.22,
        "business_weight": 0.70,
        "individual_weight": 0.25,
        "safety_weight": 0.05,
    },
    "E7": {
        "target_award": 0.29,
        "business_weight": 0.70,
        "individual_weight": 0.25,
        "safety_weight": 0.05,
    },
    "E8": {
        "target_award": 0.36,
        "business_weight": 0.70,
        "individual_weight": 0.25,
        "safety_weight": 0.05,
    },
    "E9": {
        "target_award": 0.48,
        "business_weight": 0.70,
        "individual_weight": 0.25,
        "safety_weight": 0.05,
    },
    "E10": {
        "target_award": 0.54,
        "business_weight": 0.70,
        "individual_weight": 0.25,
        "safety_weight": 0.05,
    },
    "E11": {
        "target_award": 0.60,
        "business_weight": 0.70,
        "individual_weight": 0.25,
        "safety_weight": 0.05,
    },
    # Add more bands as needed
}


def calculate_award(
    base_salary, band, business_result, individual_result, safety_result
):
    if band not in band_values:
        raise ValueError(f"Band {band} is not defined in the band values.")

    # Extract the target award percentages
    band_data = band_values[band]
    target_award = band_data["target_award"]
    business_weight = band_data["business_weight"]
    individual_weight = band_data["individual_weight"]
    safety_weight = band_data["safety_weight"]

    # Convert result percentages to decimals
    business_result = business_result / 100.0
    individual_result = individual_result / 100.0
    safety_result = safety_result / 100.0

    # Calculate the target bonus
    target_bonus = base_salary * target_award

    # Calculate contributions
    business_contribution = target_bonus * business_weight
    individual_contribution = target_bonus * individual_weight
    safety_contribution = target_bonus * safety_weight

    # Calculate actual contributions
    actual_business = business_contribution * business_result
    actual_individual = individual_contribution * individual_result
    actual_safety = safety_contribution * safety_result

    total_award = actual_business + actual_individual + actual_safety

    return {
        "Target Bonus": target_bonus,
        "Business Contribution": business_contribution,
        "Individual Contribution": individual_contribution,
        "Safety Contribution": safety_contribution,
        "Actual Business": actual_business,
        "Actual Individual": actual_individual,
        "Actual Safety": actual_safety,
        "Total Award": total_award,
    }


# Sample input values (these would be taken from user input in a real app)
base_salary = float(input("Enter Base Salary: "))
band = input("Enter Band: ")
business_result = float(input("Enter Business Result (as a percentage): "))
individual_result = float(input("Enter Individual Result (as a percentage): "))
safety_result = float(input("Enter Safety Result (as a percentage): "))

# Perform the calculation
results = calculate_award(
    base_salary, band, business_result, individual_result, safety_result
)

# Print the results
print(f"Target Bonus: ${results['Target Bonus']:.2f}")
print(f"Business Contribution: ${results['Business Contribution']:.2f}")
print(f"Individual Contribution: ${results['Individual Contribution']:.2f}")
print(f"Safety Contribution: ${results['Safety Contribution']:.2f}")
print(f"Actual Business: ${results['Actual Business']:.2f}")
print(f"Actual Individual: ${results['Actual Individual']:.2f}")
print(f"Actual Safety: ${results['Actual Safety']:.2f}")
print(f"Total Award: ${results['Total Award']:.2f}")

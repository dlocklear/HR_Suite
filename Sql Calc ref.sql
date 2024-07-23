CREATE OR REPLACE FUNCTION calculate_award(
        base_salary DECIMAL,
        band VARCHAR,
        business_result DECIMAL,
        individual_result DECIMAL,
        safety_result DECIMAL
    ) RETURNS TABLE (
        target_bonus DECIMAL,
        business_contribution DECIMAL,
        individual_contribution DECIMAL,
        safety_contribution DECIMAL,
        actual_business DECIMAL,
        actual_individual DECIMAL,
        actual_safety DECIMAL,
        total_award DECIMAL
    ) AS $$ BEGIN RETURN QUERY
SELECT base_salary * pg.target_award AS target_bonus,
    (base_salary * pg.target_award) * pg.business_weight AS business_contribution,
    (base_salary * pg.target_award) * pg.individual_weight AS individual_contribution,
    (base_salary * pg.target_award) * pg.safety_weight AS safety_contribution,
    (
        (base_salary * pg.target_award) * pg.business_weight
    ) * (business_result / 100) AS actual_business,
    (
        (base_salary * pg.target_award) * pg.individual_weight
    ) * (individual_result / 100) AS actual_individual,
    (
        (base_salary * pg.target_award) * pg.safety_weight
    ) * (safety_result / 100) AS actual_safety,
    (
        (base_salary * pg.target_award) * pg.business_weight
    ) * (business_result / 100) + (
        (base_salary * pg.target_award) * pg.individual_weight
    ) * (individual_result / 100) + (
        (base_salary * pg.target_award) * pg.safety_weight
    ) * (safety_result / 100) AS total_award
FROM pay_grades pg
WHERE pg.band = band;
END;
$$ LANGUAGE plpgsql;
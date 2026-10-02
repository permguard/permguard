@alias("billing-ro")
permit (
    principal in Group::"finance",
    action == Action::"read",
    resource
);

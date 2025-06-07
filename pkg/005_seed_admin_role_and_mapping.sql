-- File: prism-auth-service/migrations/005_seed_admin_role_and_mapping.sql

-- This script seeds the initial System Administrator role and its mapping to an AD group.
-- This solves the chicken-and-egg problem for the first administrator login.

DO $$
DECLARE
    -- We use a static UUID for the admin role to make the mapping predictable.
    admin_role_id UUID := 'a1d1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5';
    admin_permissions JSONB := '{
        "users": ["create", "read", "update", "delete", "manage_roles", "read_roles"],
        "roles": ["create", "read", "update", "delete"],
        "system": ["manage_settings", "manage_ad_mappings"]
    }';
BEGIN
    -- 1. Insert the System Administrator role into the default tenant's schema.
    -- We use ON CONFLICT DO NOTHING to make this script safe to re-run.
    RAISE NOTICE 'Seeding System Administrator role (ID: %) into schema tenant_default...', admin_role_id;
    INSERT INTO tenant_default.roles (id, name, tenant_id, permissions)
    VALUES (
        admin_role_id,
        'System Administrator',
        'default',
        admin_permissions
    )
    ON CONFLICT (id) DO NOTHING;

    -- Also handle potential conflict on the unique index (name, tenant_id)
    INSERT INTO tenant_default.roles (id, name, tenant_id, permissions)
    SELECT admin_role_id, 'System Administrator', 'default', admin_permissions
    WHERE NOT EXISTS (
        SELECT 1 FROM tenant_default.roles WHERE name = 'System Administrator' AND tenant_id = 'default'
    );


    -- 2. Create the mapping from the "ERP_Admins" AD group to the System Administrator role in the public schema.
    RAISE NOTICE 'Seeding AD Group Mapping for ERP_Admins to Role ID %...', admin_role_id;
    INSERT INTO public.ad_group_role_mappings (ad_group_name, role_id, tenant_id)
    VALUES (
        'ERP_Admins',
        admin_role_id,
        'default'
    )
    ON CONFLICT (tenant_id, ad_group_name, role_id) DO NOTHING;

    RAISE NOTICE 'Admin role and mapping seeding complete.';

EXCEPTION
    WHEN OTHERS THEN
        RAISE WARNING 'An error occurred during seeding: %', SQLERRM;
END $$;

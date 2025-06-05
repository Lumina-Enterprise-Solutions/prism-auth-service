-- 1. Tambahkan kolom tenant_id ke tabel users dan roles jika belum ada dan jadikan NOT NULL
-- Ini adalah contoh untuk skema tenant_default. Ulangi untuk skema tenant lainnya jika ada.
DO $$
DECLARE
    tenant_schema_name TEXT;
BEGIN
    -- Loop melalui semua skema yang dimulai dengan 'tenant_'
    FOR tenant_schema_name IN
        SELECT schema_name FROM information_schema.schemata WHERE schema_name LIKE 'tenant_%'
    LOOP
        RAISE NOTICE 'Updating schema: %', tenant_schema_name;

        -- Modifikasi tabel users
        EXECUTE format('ALTER TABLE %I.users ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);', tenant_schema_name);
        -- Isi tenant_id berdasarkan nama skema (misalnya, jika tenant_id = 'default' untuk skema 'tenant_default')
        -- Anda mungkin perlu logika yang lebih baik di sini jika slug tenant berbeda dari bagian akhir nama skema
        EXECUTE format('UPDATE %I.users SET tenant_id = %L WHERE tenant_id IS NULL;', tenant_schema_name, REPLACE(tenant_schema_name, 'tenant_', ''));
        EXECUTE format('ALTER TABLE %I.users ALTER COLUMN tenant_id SET NOT NULL;', tenant_schema_name);
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_users_tenant_id_%s ON %I.users(tenant_id);', REPLACE(tenant_schema_name, 'tenant_', ''), tenant_schema_name);

        EXECUTE format('ALTER TABLE %I.users ADD COLUMN IF NOT EXISTS ad_user_principal_name VARCHAR(255);', tenant_schema_name);
        EXECUTE format('ALTER TABLE %I.users ADD COLUMN IF NOT EXISTS ad_object_id VARCHAR(255);', tenant_schema_name);
        EXECUTE format('ALTER TABLE %I.users ADD COLUMN IF NOT EXISTS is_ad_managed BOOLEAN DEFAULT false;', tenant_schema_name);
        EXECUTE format('ALTER TABLE %I.users ADD COLUMN IF NOT EXISTS last_ad_sync TIMESTAMPTZ;', tenant_schema_name);

        -- Indeks untuk kolom AD di tabel users
        EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%s_users_ad_upn ON %I.users(ad_user_principal_name);', REPLACE(tenant_schema_name, 'tenant_', ''), tenant_schema_name);
        -- Membuat ad_object_id unik secara global (jika hanya satu AD Forest). Jika tidak, ini perlu unik per tenant_id.
        -- Untuk kesederhanaan awal, kita tidak enforce UNIQUE di sini via migrasi skema tenant,
        -- karena GORM akan mencoba UNIQUE global pada model User. Ini bisa jadi masalah jika ada user non-AD dengan ad_object_id NULL.
        -- Aplikasi harus memastikan keunikan ad_object_id jika diisi.
        -- Atau, jika Anda mau UNIQUE constraint di DB yang mengizinkan NULL:
        -- EXECUTE format('CREATE UNIQUE INDEX IF NOT EXISTS idx_%s_users_ad_object_id_unique ON %I.users(ad_object_id) WHERE ad_object_id IS NOT NULL;', REPLACE(tenant_schema_name, 'tenant_', ''), tenant_schema_name);
        -- Tapi karena GORM field `ADObjectID` memiliki `gorm:"unique"`, GORM akan mencoba membuatnya unik secara global, yang mungkin lebih baik.

        -- Modifikasi tabel roles
        EXECUTE format('ALTER TABLE %I.roles ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);', tenant_schema_name);
        EXECUTE format('UPDATE %I.roles SET tenant_id = %L WHERE tenant_id IS NULL;', tenant_schema_name, REPLACE(tenant_schema_name, 'tenant_', ''));
        EXECUTE format('ALTER TABLE %I.roles ALTER COLUMN tenant_id SET NOT NULL;', tenant_schema_name);

        -- Hapus unique constraint lama pada name jika ada (yang tidak menyertakan tenant_id)
        BEGIN
            EXECUTE format('ALTER TABLE %I.roles DROP CONSTRAINT IF EXISTS roles_name_key;', tenant_schema_name); -- Nama default jika hanya name unique
            EXECUTE format('ALTER TABLE %I.roles DROP CONSTRAINT IF EXISTS %s_roles_name_key;', tenant_schema_name, tenant_schema_name); -- Jika nama constraint menyertakan schema
            -- Cari nama constraint unik yang hanya melibatkan kolom 'name' dan drop
             DECLARE
            constraint_name_to_drop TEXT;
        BEGIN
            SELECT con.conname INTO constraint_name_to_drop
            FROM pg_catalog.pg_constraint con
            INNER JOIN pg_catalog.pg_class rel ON rel.oid = con.conrelid
            INNER JOIN pg_catalog.pg_namespace nsp ON nsp.oid = rel.relnamespace
            WHERE nsp.nspname = tenant_schema_name  -- Nama skema
              AND rel.relname = 'roles'           -- Nama tabel
              AND con.contype = 'u'               -- Unique constraint
              AND array_length(con.conkey, 1) = 1 -- Hanya satu kolom dalam constraint
              AND (SELECT pg_catalog.col_description(con.conrelid, con.conkey[1])) IS NOT NULL -- Pastikan kolom ada
              AND (SELECT att.attname FROM pg_catalog.pg_attribute att WHERE att.attrelid = con.conrelid AND att.attnum = con.conkey[1] AND NOT att.attisdropped) = 'name' -- Kolomnya adalah 'name'
            LIMIT 1;

            IF constraint_name_to_drop IS NOT NULL THEN
                RAISE NOTICE 'Dropping old unique constraint % on %.roles(name)', constraint_name_to_drop, tenant_schema_name;
                EXECUTE format('ALTER TABLE %I.roles DROP CONSTRAINT %I;', tenant_schema_name, constraint_name_to_drop);
            ELSE
                RAISE NOTICE 'No old single-column unique constraint found on %.roles(name) to drop.', tenant_schema_name;
            END IF;
        EXCEPTION
            WHEN undefined_object THEN -- Atau error spesifik lain jika DROP gagal karena tidak ada
                RAISE NOTICE 'Old unique constraint on %.roles(name) not found or already dropped, or error during drop.', tenant_schema_name;
            WHEN others THEN
                RAISE WARNING 'An unexpected error occurred while trying to drop constraint on %.roles(name): %', tenant_schema_name, SQLERRM;
        END;
        END;


        EXECUTE format('CREATE UNIQUE INDEX IF NOT EXISTS idx_role_name_tenant_id_%s ON %I.roles(name, tenant_id);', REPLACE(tenant_schema_name, 'tenant_', ''), tenant_schema_name);

    END LOOP;
END $$;


-- 2. Buat tabel ad_group_role_mappings di skema public
CREATE TABLE IF NOT EXISTS public.ad_group_role_mappings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ad_group_name VARCHAR(255) NOT NULL,
    role_id UUID NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ,
    -- Memastikan bahwa satu grup AD dalam satu tenant hanya bisa di-map ke satu role sistem.
    -- Jika Anda ingin 1 grup AD bisa map ke banyak role, hapus role_id dari constraint ini
    -- atau buat constraint pada (tenant_id, ad_group_name, role_id).
    -- Untuk saat ini: 1 AD Group per tenant -> 1 Role Sistem.
    CONSTRAINT uq_ad_mapping_tenant_adgroup_role UNIQUE (tenant_id, ad_group_name, role_id)
);

CREATE INDEX IF NOT EXISTS idx_ad_group_role_mappings_tenant_id ON public.ad_group_role_mappings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ad_group_role_mappings_role_id ON public.ad_group_role_mappings(role_id);
CREATE INDEX IF NOT EXISTS idx_ad_group_role_mappings_ad_group_name ON public.ad_group_role_mappings(ad_group_name);

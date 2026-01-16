    def table_exists(self, table_name: str) -> bool:
        """Vérifie si une table existe (Compatibilité Legacy)."""
        self.open()
        try:
            self.cursor.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name = %s
                );
            """, (table_name,))
            return self.cursor.fetchone()[0]
        except Exception as e:
            print(f"[PGSQL] Erreur table_exists: {e}")
            return False
        finally:
            self.close()

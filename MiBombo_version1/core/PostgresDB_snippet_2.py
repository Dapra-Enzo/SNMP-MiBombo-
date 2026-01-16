    def getChamps(self, table: str) -> list:
        """Récupère la liste des champs d'une table."""
        self.open()
        try:
            self.cursor.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = %s 
                ORDER BY ordinal_position
            """, (table,))
            return [row[0] for row in self.cursor.fetchall()]
        except Exception as e:
            print(f"[PGSQL] Erreur getChamps: {e}")
            return []
        finally:
            self.close()

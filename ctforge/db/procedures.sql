
-- CTForge: Forge your own CTF.

-- Copyright (C) 2016-2019  Marco Squarcina
-- Copyright (C) 2016-2019  Mauro Tempesta
-- Copyright (C) 2016-2019  Lorenzo Veronese

-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU Affero General Public License as published
-- by the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.

-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU Affero General Public License for more details.

-- You should have received a copy of the GNU Affero General Public License
-- along with this program.  If not, see <https://www.gnu.org/licenses/>.

/* Get the ID of the current round. */
CREATE OR REPLACE FUNCTION get_current_round() RETURNS INT AS $$
DECLARE
  current_round INT;
BEGIN
  SELECT MAX(id) INTO current_round FROM rounds;
  RETURN current_round;
END;
$$ LANGUAGE plpgsql;

/* The trigger creates an empty score row upon team insertion. */
CREATE OR REPLACE FUNCTION add_score_entry() RETURNS TRIGGER AS $$
DECLARE
  current_round INT;
BEGIN
  /* Pick the current round from the rounds table: if the table is empty
   * (this happens only when the first team is added to the DB), add a
   * row with round 0. */
  SELECT get_current_round() INTO current_round;
  IF current_round IS NULL THEN
    current_round := 0;
    INSERT INTO rounds (id) VALUES (current_round);
  END IF;
  /* Use the function GREATEST to avoid inserting scores with round -1 when
   * the CTF is not started yet. */
  INSERT INTO scores
  SELECT GREATEST(current_round - 1, 0), NEW.id, id, 0, 0, 0

  FROM services;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS fill_scores_table ON teams;
CREATE TRIGGER fill_scores_table
AFTER INSERT ON teams FOR EACH ROW
EXECUTE PROCEDURE add_score_entry();

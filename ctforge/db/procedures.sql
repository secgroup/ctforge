/*
The procedure performs the following operations:
- computes the number of total and successful checks performed by the bot
  for each team and service (thus for each active flag) in the current round;
- computes the score for the current round for each team;
- clears active_flags and integrity_checks tables in order to start with the
  next round.

Formulae used for scores computation of the current round (per service):
- integrity = #upChecks / #n_checks
- attack = #attacks
- defense = int((0 if integrity < 0.8 else integrity) * (#teams - 1 - #attacks_received))
*/

CREATE OR REPLACE FUNCTION switch_round() RETURNS INT AS $$
DECLARE
  current_round INT;
  n_teams INT;
  integrity_checks_cursor CURSOR FOR
    SELECT UC.flag, UC.n_up_checks, NC.n_checks
    FROM (
      SELECT AF.flag, COUNT(I.flag) AS n_up_checks
      FROM active_flags AF LEFT JOIN integrity_checks I ON (AF.flag = I.flag AND I.successful)
      GROUP BY AF.flag
    ) AS UC, (
      SELECT AF.flag, COUNT(I.flag) AS n_checks
      FROM active_flags AF LEFT JOIN integrity_checks I ON AF.flag = I.flag
      GROUP BY AF.flag
    ) AS NC
    WHERE UC.flag = NC.flag;
BEGIN
  /* Get the current round. */
  SELECT MAX(id) INTO current_round FROM rounds;
  
  /* Avoid recomputing the scores at the beginning of the CTF. */
  IF current_round != 0 THEN
    /* Compute the number of successful and total integrity checks for each team and
     * each service. */
    FOR flag_check IN integrity_checks_cursor LOOP
      UPDATE flags
      SET n_up_checks = flag_check.n_up_checks, n_checks = flag_check.n_checks
      WHERE flag = flag_check.flag;
    END LOOP;

    /* Get the number of teams. */
    SELECT COUNT(*) INTO n_teams FROM teams;
    /* Lock the attacks table, so to prevent race conditions between the computation of scores and the deletion
     * of active flags. The lock is automatically released at the end of the procedure. */
    LOCK TABLE service_attacks IN ACCESS EXCLUSIVE MODE;

    /* Compute scores for the current round. */
    INSERT INTO scores
      SELECT previous_scores.team_id, current_round, COALESCE(partial_scores.attack, 0) + previous_scores.attack,
        COALESCE(partial_scores.defense, 0) + previous_scores.defense
      FROM (
        /* Scores for the current round, which must be added to those of the previous round. */
        SELECT IC.team_id, SUM(AP.attacks_performed) AS attack,
          SUM(TRUNC((CASE WHEN IC.integrity < 0.8 THEN 0 ELSE IC.integrity END) * (n_teams - 1 - AR.attacks_received))) AS defense
        FROM (
          /* The first query retrieves the number of attacks by each team against each service for
          which at least an attack has been performed in the current round, the second one sets to
          0 the number of attacks for the remaining services. */
          SELECT A.team_id, AF.service_id, COUNT(A.flag) AS attacks_performed
          FROM active_flags AF JOIN service_attacks A ON (AF.flag = A.flag)
          GROUP BY A.team_id, AF.service_id

          UNION

          SELECT T.id AS team_id, S.id AS service_id, 0 AS attacks_performed
          FROM teams T, services S
          WHERE T.id NOT IN (
            SELECT A.team_id
            FROM active_flags AF JOIN service_attacks A ON (AF.flag = A.flag)
            WHERE AF.service_id = S.id
          )
        ) AS AP, (
          /* Compute the number of attacks received by each team on each service. */
          SELECT AF.team_id, AF.service_id, COUNT(A.flag) AS attacks_received
          FROM active_flags AF LEFT JOIN service_attacks A ON (AF.flag = A.flag)
          GROUP BY AF.team_id, AF.service_id
        ) AS AR, (
          /* Retrieve integrity information computed before from flags table. */
          SELECT AF.team_id, AF.service_id, (CASE WHEN F.n_checks > 0 THEN F.n_up_checks::float / F.n_checks ELSE 0 END) AS integrity
          FROM active_flags AF, flags F
          WHERE AF.flag = F.flag
        ) AS IC
        WHERE IC.team_id = AP.team_id AND IC.team_id = AR.team_id
        AND IC.service_id = AP.service_id AND IC.service_id = AR.service_id
        GROUP BY IC.team_id
      ) AS partial_scores RIGHT JOIN (
        /* Previous round scores (notice that there is a round 0 initialized to 0 attack
        and 0 defense for each team, so we do not have to consider a particular case for
        the first round). */
        SELECT team_id, attack, defense
        FROM scores
        WHERE round = current_round - 1
      ) AS previous_scores ON (partial_scores.team_id = previous_scores.team_id);

    /* Clear active_flags and integrity_checks tables. */
    TRUNCATE active_flags CASCADE;
  END IF;

  /* Insert the new round to the DB and return its id. */
  INSERT INTO rounds (id) VALUES (current_round + 1);
  RETURN current_round + 1;
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
  SELECT MAX(id) INTO current_round FROM rounds;
  IF current_round IS NULL THEN
    current_round := 0;
    INSERT INTO rounds (id) VALUES (current_round);
  END IF;
  /* Use the function GREATEST to avoid inserting scores with round -1 when
   * the CTF is not started yet. */
  INSERT INTO scores VALUES (NEW.id, GREATEST(current_round - 1, 0), 0, 0);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS fill_scores_table ON teams;
CREATE TRIGGER fill_scores_table
AFTER INSERT ON teams FOR EACH ROW
EXECUTE PROCEDURE add_score_entry();

/* The trigger adds the flag just inserted into flags also into active_flags. */
CREATE OR REPLACE FUNCTION add_active_flag() RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO active_flags VALUES (NEW.flag, NEW.team_id, NEW.service_id, NEW.round);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS fill_active_flags_table ON flags;
CREATE TRIGGER fill_active_flags_table
AFTER INSERT ON flags FOR EACH ROW
EXECUTE PROCEDURE add_active_flag();
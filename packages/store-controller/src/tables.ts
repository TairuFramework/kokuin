import type { CreatedAtColumn, UpdatedAtColumn } from '@hozon/adapter'
import type { SignedEvent } from '@kokuin/controller'
import type { ColumnType, Insertable, Selectable } from 'kysely'

// The stored log round-trips through the adapter's JSON column: `encodeJSON`
// stringifies on SQLite and passes through on Postgres, so the same value
// serves select, insert and update.
type JSONValueColumn<T> = ColumnType<T, T, T>

export type ControllerLogTable = {
  did: string
  log: JSONValueColumn<Array<SignedEvent>>
  created_at: CreatedAtColumn
  updated_at: UpdatedAtColumn
}

export type ControllerLogRow = Selectable<ControllerLogTable>
export type InsertControllerLog = Insertable<ControllerLogTable>

export type ControllerStoreTables = {
  controller_logs: ControllerLogTable
}

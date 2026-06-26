using Data.Actions;
using Data.Actions.Notify;
using Data.Events;
using System.Collections.Generic;
using Tera.Game;

namespace DamageMeter.UI
{
    public class BaseEventViewModel : TSPropertyChanged
    {
        protected readonly Event Event;
        private bool _active;
        private bool _ingame;
        private int _priority;
        private bool _outOfCombat;

        public bool Active
        {
            get => _active;
            set
            {
                if (_active == value) return;
                _active = value;
                Event.Active = value;
                NotifyPropertyChanged();
                NotifyPropertyChanged(nameof(SearchText));
            }
        }

        public bool InGame
        {
            get => _ingame;
            set
            {
                if (_ingame == value) return;
                _ingame = value;
                Event.InGame = value;
                NotifyPropertyChanged();
                NotifyPropertyChanged(nameof(SearchText));
            }
        }

        public bool OutOfCombat
        {
            get => _outOfCombat;
            set
            {
                if (_outOfCombat == value) return;
                _outOfCombat = value;
                Event.OutOfCombat = value;
                NotifyPropertyChanged();
                NotifyPropertyChanged(nameof(SearchText));
            }
        }

        public int Priority
        {
            get => _priority;
            set
            {
                if (_priority == value) return;
                _priority = value;
                Event.Priority = value;
                NotifyPropertyChanged();
                NotifyPropertyChanged(nameof(SearchText));
            }
        }

        public virtual string Type => "Event";
        public virtual string Summary => Type;
        public virtual string SearchText => $"{Type} {Summary} {(Active ? "active" : "inactive")} {(InGame ? "ingame" : "outgame")} priority {Priority}";

        public SynchronizedObservableCollection<BlackListItemVM> BlacklistedBosses { get; }
        public SynchronizedObservableCollection<PlayerClass> BlacklistedClasses { get; }
        public SynchronizedObservableCollection<ActionVM> Actions { get; }

        public BaseEventViewModel(Event ev, List<Action> act)
        {
            Event = ev;
            BlacklistedBosses = new SynchronizedObservableCollection<BlackListItemVM>();
            BlacklistedClasses = new SynchronizedObservableCollection<PlayerClass>();
            Actions = new SynchronizedObservableCollection<ActionVM>();
            _active = ev.Active;
            _ingame = ev.InGame;
            _priority = ev.Priority;
            _outOfCombat = ev.OutOfCombat;
            ev.AreaBossBlackList.ForEach(b => BlacklistedBosses.Add(new BlackListItemVM(b.AreaId, b.BossId)));
            ev.IgnoreClasses.ForEach(BlacklistedClasses.Add);

            act.ForEach(action =>
            {
                if (action is not NotifyAction na) return;
                Actions.Add(new ActionVM(na));
            });
        }
    }
}
